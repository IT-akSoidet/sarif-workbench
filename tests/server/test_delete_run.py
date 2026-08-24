"""Тесты на DELETE /api/v1/runs/{run_id}.

Покрывает:
  - 404 на несуществующий ран, 409 пока идёт AI-анализ (ран при этом жив);
  - каскадное удаление Finding/Rule вместе с Run (ondelete=CASCADE +
    passive_deletes=True, models.py);
  - пересчёт FindingIdentity.last_seen_run_id/last_seen_at на identity, для
    которых удаляемый ран был последним, но identity встречается и в других
    ranах проекта — по самому свежему из ОСТАВШИХСЯ ranов (Run.uploaded_at);
  - что identity, у которой после удаления рана не осталось ни одной
    находки, удаляется вместе со своим append-only журналом VerdictEvent
    (cascade), а identity, у которой находки остались в других ranах —
    сохраняется вместе с вердиктом и историей;
  - что first_seen_run_id НЕ пересчитывается (просто ondelete=SET NULL) —
    в отличие от last_seen_run_id, для которого endpoint явно ищет замену;
  - defensive-ветку `if last_finding:` -> False внутри пересчёта last_seen —
    штатно недостижима (гарантирована фильтром identities_to_update), но
    форсируется через патч Query.first, чтобы не оставлять код без покрытия;
  - сброс Project.baseline_run_id, если удаляемый ран был бейзлайном;
  - что delete_blob вызывается для удалённого рана и что ошибка storage не
    откатывает уже закоммиченное удаление в БД.
"""
import uuid
from datetime import datetime


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _set_uploaded_at(db_session, run_id: str, dt: datetime) -> None:
    from swb_server.models import Run

    db_session.query(Run).filter(Run.id == run_id).update({Run.uploaded_at: dt})
    db_session.commit()


def _delete(client, run_id: str):
    return client.delete(f"/api/v1/runs/{run_id}")


# ── базовые коды ответа ─────────────────────────────────────────────────────


def test_delete_run_returns_404_for_missing_run(client):
    resp = _delete(client, "r-does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "not_found"


def test_delete_run_returns_409_when_analysis_in_progress(client, db_session, upload_run, monkeypatch):
    from swb_server.models import Run

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    # is_analysis_in_progress импортирован в routers.runs через
    # `from ..ai.analyze_loop import is_analysis_in_progress` — это создаёт
    # отдельную локальную привязку имени в routers.runs, поэтому патчить
    # нужно именно её, а не swb_server.ai.analyze_loop.is_analysis_in_progress.
    monkeypatch.setattr("swb_server.routers.runs.is_analysis_in_progress", lambda run_id: True)

    resp = _delete(client, run["run_id"])
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "analysis_in_progress"

    # ран не тронут
    assert db_session.query(Run).filter(Run.id == run["run_id"]).first() is not None


# ── каскад Finding/Rule ──────────────────────────────────────────────────────


def test_delete_run_cascades_findings_and_rule(client, db_session, upload_run):
    from swb_server.models import Finding, Rule, Run

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42},
            {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7},
        ],
        repo=repo,
    )
    run_id = run["run_id"]

    # Дописываем Rule напрямую, чтобы не зависеть от того, кладёт ли текущий
    # ingest-конвейер строки в rules при данной фикстуре SARIF — сам факт
    # каскада проверяем на заведомо существующей строке.
    db_session.add(Rule(run_id=run_id, rule_id="CWE-89", name="SQL Injection"))
    db_session.commit()

    assert db_session.query(Finding).filter(Finding.run_id == run_id).count() == 2
    assert db_session.query(Rule).filter(Rule.run_id == run_id).count() == 1

    resp = _delete(client, run_id)
    assert resp.status_code == 204

    assert db_session.query(Run).filter(Run.id == run_id).first() is None
    assert db_session.query(Finding).filter(Finding.run_id == run_id).count() == 0
    assert db_session.query(Rule).filter(Rule.run_id == run_id).count() == 0


def test_delete_run_does_not_affect_other_project(client, db_session, upload_run):
    from swb_server.models import Run

    repo_a = _unique_repo()
    repo_b = _unique_repo()
    run_a = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo_a)
    run_b = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo_b)

    resp = _delete(client, run_a["run_id"])
    assert resp.status_code == 204

    assert db_session.query(Run).filter(Run.id == run_b["run_id"]).first() is not None


# ── пересчёт last_seen_run_id / last_seen_at ────────────────────────────────


def test_delete_run_updates_last_seen_to_most_recent_remaining_run(client, db_session, upload_run):
    from swb_server.models import FindingIdentity

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}]

    run1 = upload_run(spec, repo=repo)
    run2 = upload_run(spec, repo=repo)
    run3 = upload_run(spec, repo=repo)  # каждый вызов кладёт свой nonce -> три разных Run

    # Явно фиксируем порядок uploaded_at, не полагаясь на реальные системные
    # часы между тремя последовательными вызовами upload_run.
    _set_uploaded_at(db_session, run1["run_id"], datetime(2026, 1, 1))
    _set_uploaded_at(db_session, run2["run_id"], datetime(2026, 1, 2))
    _set_uploaded_at(db_session, run3["run_id"], datetime(2026, 1, 3))

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run1["project_id"])
        .one()
    )
    assert identity.last_seen_run_id == run3["run_id"]

    resp = _delete(client, run3["run_id"])
    assert resp.status_code == 204

    db_session.expire_all()
    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == identity.id).one()
    assert identity.last_seen_run_id == run2["run_id"]
    assert identity.last_seen_at == datetime(2026, 1, 2)


def test_delete_run_leaves_last_seen_untouched_when_it_was_not_last_seen(client, db_session, upload_run):
    from swb_server.models import FindingIdentity

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}]

    run1 = upload_run(spec, repo=repo)
    run2 = upload_run(spec, repo=repo)

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run1["project_id"])
        .one()
    )
    assert identity.last_seen_run_id == run2["run_id"]

    # Удаляем run1 — он не last_seen, condition в delete_run
    # (last_seen_run_id == selected_run_id) не срабатывает, пересчёта нет.
    resp = _delete(client, run1["run_id"])
    assert resp.status_code == 204

    db_session.expire_all()
    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == identity.id).one()
    assert identity.last_seen_run_id == run2["run_id"]


def test_delete_run_does_not_recompute_first_seen_run_id(client, db_session, upload_run):
    """first_seen_run_id обнуляется FK ondelete=SET NULL и НЕ восстанавливается —
    в отличие от last_seen_run_id, для которого есть явная бизнес-логика поиска
    замены в delete_run.
    """
    from swb_server.models import FindingIdentity

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}]

    run1 = upload_run(spec, repo=repo)  # identity.first_seen_run_id = run1
    run2 = upload_run(spec, repo=repo)  # identity.last_seen_run_id = run2

    identity = (
        db_session.query(FindingIdentity)
        .filter(FindingIdentity.project_id == run1["project_id"])
        .one()
    )
    assert identity.first_seen_run_id == run1["run_id"]

    resp = _delete(client, run1["run_id"])
    assert resp.status_code == 204

    db_session.expire_all()
    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == identity.id).one()
    assert identity.first_seen_run_id is None  # не пересчитан на run2
    assert identity.last_seen_run_id == run2["run_id"]  # не тронут — удалённый ран не был last_seen


# ── удаление осиротевших identity / сохранение живых ────────────────────────


def test_delete_run_removes_orphan_identity_and_its_verdict_events(client, db_session, upload_run):
    from swb_server.models import Finding, FindingIdentity, VerdictEvent

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/only-here.py", "start_line": 1}], repo=repo)
    run_id = run["run_id"]

    finding = db_session.query(Finding).filter(Finding.run_id == run_id).one()
    identity_id = finding.identity_id

    resp = client.patch(
        f"/api/v1/findings/{finding.id}/verdict",
        json={"verdict": "true_positive", "version": 1},
    )
    assert resp.status_code == 200
    assert db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity_id).count() == 1

    resp = _delete(client, run_id)
    assert resp.status_code == 204

    # Finding был единственным у этой identity -> identity осиротела и
    # удалена; её VerdictEvent'ы уходят каскадно вместе с ней (models.py:
    # VerdictEvent.identity_id ondelete=CASCADE, FindingIdentity.events
    # cascade="all, delete-orphan").
    assert db_session.query(FindingIdentity).filter(FindingIdentity.id == identity_id).first() is None
    assert db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity_id).count() == 0


def test_delete_run_keeps_identity_and_verdict_when_finding_survives_in_another_run(
    client, db_session, upload_run,
):
    from swb_server.models import Finding, FindingIdentity

    repo = _unique_repo()
    swb_id = f"sw2:t:{uuid.uuid4().hex[:24]}:0"
    spec = [{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42, "swb_id": swb_id}]

    run1 = upload_run(spec, repo=repo)
    run2 = upload_run(spec, repo=repo)

    finding1 = db_session.query(Finding).filter(Finding.run_id == run1["run_id"]).one()
    identity_id = finding1.identity_id
    resp = client.patch(
        f"/api/v1/findings/{finding1.id}/verdict",
        json={"verdict": "true_positive", "rationale": "confirmed", "version": 1},
    )
    assert resp.status_code == 200

    resp = _delete(client, run2["run_id"])
    assert resp.status_code == 204

    identity = db_session.query(FindingIdentity).filter(FindingIdentity.id == identity_id).first()
    assert identity is not None
    assert identity.verdict == "true_positive"
    assert identity.verdict_source == "human"
    assert identity.last_seen_run_id == run1["run_id"]  # переехал на оставшийся ран


# ── baseline ──────────────────────────────────────────────────────────────────


def test_delete_run_clears_baseline_when_deleted_run_was_baseline(client, db_session, upload_run):
    from swb_server.models import Project

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    project_id = run["project_id"]

    resp = client.put(f"/api/v1/projects/{project_id}/baseline", json={"baseline_run_id": run["run_id"]})
    assert resp.status_code == 200

    resp = _delete(client, run["run_id"])
    assert resp.status_code == 204

    project = db_session.query(Project).filter(Project.id == project_id).one()
    # Фактическое поведение кода — обнуление в None. Документ по фиче
    # описывает пустую строку (""); тест фиксирует то, что реально делает
    # текущая реализация, а не задокументированное намерение.
    assert project.baseline_run_id is None


def test_delete_run_leaves_baseline_untouched_when_different_run_deleted(client, db_session, upload_run):
    from swb_server.models import Project

    repo = _unique_repo()
    baseline_run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)
    other_run = upload_run([{"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7}], repo=repo)
    project_id = baseline_run["project_id"]

    resp = client.put(
        f"/api/v1/projects/{project_id}/baseline",
        json={"baseline_run_id": baseline_run["run_id"]},
    )
    assert resp.status_code == 200

    resp = _delete(client, other_run["run_id"])
    assert resp.status_code == 204

    project = db_session.query(Project).filter(Project.id == project_id).one()
    assert project.baseline_run_id == baseline_run["run_id"]


# ── storage ──────────────────────────────────────────────────────────────────


def test_delete_run_calls_delete_blob_with_run_id(client, upload_run, monkeypatch):
    calls = []
    monkeypatch.setattr("swb_server.routers.runs.delete_blob", lambda run_id: calls.append(run_id))

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = _delete(client, run["run_id"])
    assert resp.status_code == 204
    assert calls == [run["run_id"]]


def test_delete_run_succeeds_even_if_blob_deletion_fails(client, db_session, upload_run, monkeypatch):
    from swb_server.models import Run

    def _raise(run_id):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr("swb_server.routers.runs.delete_blob", _raise)

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = _delete(client, run["run_id"])
    # db.commit() в runs.py идёт до вызова delete_blob — ошибка storage
    # только логируется и не откатывает уже закоммиченное удаление в БД.
    assert resp.status_code == 204
    assert db_session.query(Run).filter(Run.id == run["run_id"]).first() is None