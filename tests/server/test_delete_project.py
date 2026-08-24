"""Тесты на DELETE /api/v1/projects/{project_id}.

Покрывает:
  - 404 на несуществующий проект, 409 если у ЛЮБОГО его рана идёт AI-анализ
    (проект при этом не тронут);
  - каскадное удаление всего дерева проекта (Run/Finding/Rule/FindingIdentity/
    VerdictEvent) одним `db.delete(project)` за счёт ondelete=CASCADE +
    passive_deletes=True в models.py;
  - что удаление одного проекта не задевает другие;
  - что delete_blob вызывается на каждый ран удалённого проекта, и что
    db.commit() в БД происходит ДО попытки чистки storage — ошибка storage
    не откатывает уже удалённый проект;
  - фактическое (не идеальное) поведение цикла удаления blob'ов: весь цикл
    обёрнут ОДНИМ try/except в projects.py, поэтому исключение на одном
    run_id прерывает цикл целиком — delete_blob для остальных ranов этого
    проекта в этом вызове вообще не пытается выполниться;
  - удаление проекта без ranов (пустое дерево) проходит без ошибок.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def _delete(client, project_id: str):
    return client.delete(f"/api/v1/projects/{project_id}")


# ── базовые коды ответа ─────────────────────────────────────────────────────


def test_delete_project_returns_404_for_missing_project(client):
    resp = _delete(client, "does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "not_found"


def test_delete_project_returns_409_when_any_run_has_analysis_in_progress(
    client, db_session, upload_run, monkeypatch,
):
    from swb_server.models import Project

    repo = _unique_repo()
    run1 = upload_run([{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1}], repo=repo)
    run2 = upload_run([{"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2}], repo=repo)

    # AI-анализ идёт только у ВТОРОГО рана проекта — 409 должен сработать за
    # счёт `any(...)` по всем ranам проекта, а не только по первому найденному.
    target_run_id = run2["run_id"]
    monkeypatch.setattr(
        "swb_server.routers.projects.is_analysis_in_progress",
        lambda run_id: run_id == target_run_id,
    )

    resp = _delete(client, run1["project_id"])
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "analysis_in_progress"

    # проект не тронут
    assert db_session.query(Project).filter(Project.id == run1["project_id"]).first() is not None


# ── каскад ────────────────────────────────────────────────────────────────────


def test_delete_project_cascades_full_tree(client, db_session, upload_run):
    from swb_server.models import Finding, FindingIdentity, Project, Rule, Run, VerdictEvent

    repo = _unique_repo()
    run = upload_run(
        [
            {"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42},
            {"rule_id": "CWE-79", "uri": "src/web.py", "start_line": 7},
        ],
        repo=repo,
    )
    project_id = run["project_id"]
    run_id = run["run_id"]

    # Дописываем Rule напрямую, чтобы каскад Rule проверялся независимо от
    # того, кладёт ли текущий ingest-конвейер строки в rules для этой фикстуры.
    db_session.add(Rule(run_id=run_id, rule_id="CWE-89", name="SQL Injection"))
    db_session.commit()

    finding = db_session.query(Finding).filter(Finding.run_id == run_id).first()
    resp = client.patch(
        f"/api/v1/findings/{finding.id}/verdict",
        json={"verdict": "true_positive", "version": 1},
    )
    assert resp.status_code == 200
    identity_id = finding.identity_id

    # sanity: перед удалением всё реально существует
    assert db_session.query(Run).filter(Run.project_id == project_id).count() == 1
    assert db_session.query(Finding).filter(Finding.run_id == run_id).count() == 2
    assert db_session.query(Rule).filter(Rule.run_id == run_id).count() == 1
    assert db_session.query(FindingIdentity).filter(FindingIdentity.project_id == project_id).count() == 2
    assert db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity_id).count() == 1

    resp = _delete(client, project_id)
    assert resp.status_code == 204

    assert db_session.query(Project).filter(Project.id == project_id).first() is None
    assert db_session.query(Run).filter(Run.project_id == project_id).count() == 0
    assert db_session.query(Finding).filter(Finding.run_id == run_id).count() == 0
    assert db_session.query(Rule).filter(Rule.run_id == run_id).count() == 0
    assert db_session.query(FindingIdentity).filter(FindingIdentity.project_id == project_id).count() == 0
    assert db_session.query(VerdictEvent).filter(VerdictEvent.identity_id == identity_id).count() == 0


def test_delete_project_does_not_affect_other_project(client, db_session, upload_run):
    from swb_server.models import Project, Run

    repo_a = _unique_repo()
    repo_b = _unique_repo()
    run_a = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo_a)
    run_b = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo_b)

    resp = _delete(client, run_a["project_id"])
    assert resp.status_code == 204

    assert db_session.query(Project).filter(Project.id == run_b["project_id"]).first() is not None
    assert db_session.query(Run).filter(Run.id == run_b["run_id"]).first() is not None


def test_delete_project_with_no_runs_succeeds(client, db_session):
    from swb_server.models import Project

    repo = _unique_repo()
    project = Project(id=repo, repo=repo, name=repo)
    db_session.add(project)
    db_session.commit()

    resp = _delete(client, project.id)
    assert resp.status_code == 204
    assert db_session.query(Project).filter(Project.id == project.id).first() is None


# ── storage ──────────────────────────────────────────────────────────────────


def test_delete_project_calls_delete_blob_for_every_run(client, upload_run, monkeypatch):
    calls = []
    monkeypatch.setattr("swb_server.routers.projects.delete_blob", lambda run_id: calls.append(run_id))

    repo = _unique_repo()
    run1 = upload_run([{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1}], repo=repo)
    run2 = upload_run([{"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2}], repo=repo)

    resp = _delete(client, run1["project_id"])
    assert resp.status_code == 204
    assert sorted(calls) == sorted([run1["run_id"], run2["run_id"]])


def test_delete_project_succeeds_even_if_blob_deletion_fails(client, db_session, upload_run, monkeypatch):
    from swb_server.models import Project

    def _raise(run_id):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr("swb_server.routers.projects.delete_blob", _raise)

    repo = _unique_repo()
    run = upload_run([{"rule_id": "CWE-89", "uri": "src/db.py", "start_line": 42}], repo=repo)

    resp = _delete(client, run["project_id"])
    # db.commit() в projects.py идёт раньше try/except с delete_blob —
    # ошибка storage не откатывает уже удалённый проект.
    assert resp.status_code == 204
    assert db_session.query(Project).filter(Project.id == run["project_id"]).first() is None


def test_delete_project_blob_loop_stops_at_first_failure(client, upload_run, monkeypatch):
    """Фиксирует фактическое, не идеальное поведение: `for run_id in run_ids:
    delete_blob(run_id)` в projects.py обёрнут одним try/except на весь цикл.
    Если delete_blob падает на первом run_id, исключение прерывает цикл
    целиком — delete_blob для остальных ranов этого проекта в этом вызове
    вообще не пытается выполниться (залогируется один warning на весь проект,
    а не по одному на ран).
    """
    calls = []

    def _delete_blob(run_id):
        calls.append(run_id)
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr("swb_server.routers.projects.delete_blob", _delete_blob)

    repo = _unique_repo()
    run1 = upload_run([{"rule_id": "CWE-89", "uri": "src/a.py", "start_line": 1}], repo=repo)
    upload_run([{"rule_id": "CWE-79", "uri": "src/b.py", "start_line": 2}], repo=repo)

    resp = _delete(client, run1["project_id"])
    assert resp.status_code == 204
    # только один run_id из двух — цикл прервался на первом исключении
    assert len(calls) == 1