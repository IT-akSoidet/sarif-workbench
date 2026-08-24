import hashlib
import json
import logging
from pathlib import Path

from swb_cli.commands.enrich import _get_git_info, enrich

DATA = Path(__file__).parent.parent / "data"
VALID = DATA / "valid"
INVALID = DATA / "invalid"
MALICIOUS = DATA / "malicious"


class Args:
    """Минимальный объект аргументов для вызова enrich() напрямую."""
    def __init__(self, sarif, out=None, repo_root=None, source_root=None, context_policy="lines",
                 context_lines=5, no_git=True, fail_on_missing_source=False,
                 log_level="error"):
        self.sarif = str(sarif)
        self.out = str(out) if out else None
        self.repo_root = str(repo_root) if repo_root else None
        self.source_root = str(source_root) if source_root else None
        self.context_policy = context_policy
        self.context_lines = context_lines
        self.no_git = no_git
        self.fail_on_missing_source = fail_on_missing_source
        self.log_level = log_level


# ── exit codes ────────────────────────────────────────────────────────────────

def test_enrich_returns_0_on_valid_sarif(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(VALID / "minimal.sarif", out=out))
    assert code == 0

def test_enrich_returns_2_on_missing_file(tmp_path):
    code = enrich(Args(tmp_path / "nonexistent.sarif"))
    assert code == 2

def test_enrich_returns_1_on_malformed_json(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(INVALID / "malformed_json.sarif", out=out))
    assert code == 1

def test_enrich_returns_1_on_empty_file(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    code = enrich(Args(INVALID / "empty_file.sarif", out=out))
    assert code == 1

def test_enrich_returns_1_on_wrong_type_runs(tmp_path, caplog):
    """T-64 regression: "runs" typed as a string (not a list/object) makes
    the parser raise a bare AttributeError ("'str' object has no attribute
    'get'") — before this fix that propagated out of enrich() as an
    uncaught traceback instead of the controlled exit malformed_json/
    empty_file already get. It must now be caught and reported the same way
    (exit 1, human-readable error line), and the raw exception text must not
    land in the default (error-level) log output.
    """
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.ERROR):
        code = enrich(Args(INVALID / "wrong_type_runs.sarif", out=out))
    assert code == 1
    assert "Failed to parse SARIF" in caplog.text
    assert "has no attribute" not in caplog.text
    assert not out.exists()


# ── output correctness ────────────────────────────────────────────────────────

def test_output_is_valid_json(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["schema"] == "swbmeta/v3"

def test_sha256_matches_source_file(tmp_path):
    sarif = VALID / "minimal.sarif"
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(sarif, out=out))
    data = json.loads(out.read_text())
    expected = hashlib.sha256(sarif.read_bytes()).hexdigest()
    assert data["source_sarif"]["sha256"] == expected

def test_output_finding_count(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out))
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1

def test_empty_runs_produces_zero_findings(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "empty_runs.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["findings"] == []

def test_no_locations_finding_is_skipped(tmp_path):
    # результаты без locations не попадают в findings
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "no_locations.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["findings"] == []

def test_no_locations_result_logs_warning(tmp_path, caplog):
    # T-36: результат без locations больше не пропадает бесследно — warning в stderr-лог
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.WARNING):
        code = enrich(Args(VALID / "no_locations.sarif", out=out))
    assert code == 0
    assert "no locations" in caplog.text

def test_no_locations_result_counted_in_summary_log(tmp_path, caplog):
    # T-36: результаты без locations учитываются в счётчике итогового лога enrich()
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.INFO):
        enrich(Args(VALID / "no_locations.sarif", out=out))
    assert "0 findings" in caplog.text
    assert "1 skipped" in caplog.text

def test_mixed_located_and_locationless_results_skip_count_matches(tmp_path, caplog):
    # T-36: скипается только результат без locations; счётчик считает именно его,
    # результат с локацией по-прежнему попадает в findings.
    sarif = tmp_path / "report.sarif"
    sarif.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "TestTool", "version": "1.0", "rules": []}},
            "results": [
                {
                    "ruleId": "CWE-89", "level": "error",
                    "message": {"text": "has location"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/db.py"},
                        "region": {"startLine": 1},
                    }}],
                },
                {
                    "ruleId": "CWE-79", "level": "warning",
                    "message": {"text": "no location"},
                },
            ],
        }],
    }))
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.INFO):
        code = enrich(Args(sarif, out=out))
    assert code == 0
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1
    assert "1 findings" in caplog.text
    assert "1 skipped" in caplog.text

def test_original_sarif_not_modified(tmp_path):
    sarif = VALID / "minimal.sarif"
    original_bytes = sarif.read_bytes()
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(sarif, out=out))
    assert sarif.read_bytes() == original_bytes

def test_default_out_path_is_next_to_sarif(tmp_path):
    sarif = tmp_path / "report.sarif"
    sarif.write_bytes((VALID / "minimal.sarif").read_bytes())
    enrich(Args(sarif, out=None))
    assert (tmp_path / "report.sarif.swbmeta.json").exists()

def test_out_equal_to_input_is_rejected(tmp_path):
    sarif = tmp_path / "report.sarif"
    sarif.write_bytes((VALID / "minimal.sarif").read_bytes())
    original_bytes = sarif.read_bytes()
    original_hash = hashlib.sha256(original_bytes).hexdigest()

    code = enrich(Args(sarif, out=sarif))

    assert code != 0
    assert sarif.read_bytes() == original_bytes
    assert hashlib.sha256(sarif.read_bytes()).hexdigest() == original_hash

def test_out_equal_to_input_via_relative_path_is_rejected(tmp_path):
    # --out указывает на тот же файл, но другим (не resolved) путём:
    # через относительный сегмент "..", который после resolve() совпадает со входом.
    sub = tmp_path / "sub"
    sub.mkdir()
    sarif = tmp_path / "report.sarif"
    sarif.write_bytes((VALID / "minimal.sarif").read_bytes())
    original_bytes = sarif.read_bytes()

    relative_out = sub / ".." / "report.sarif"
    code = enrich(Args(sarif, out=relative_out))

    assert code != 0
    assert sarif.read_bytes() == original_bytes

def test_out_different_from_input_still_works(tmp_path):
    sarif = tmp_path / "report.sarif"
    sarif.write_bytes((VALID / "minimal.sarif").read_bytes())
    out = tmp_path / "report.sarif.swbmeta.json"

    code = enrich(Args(sarif, out=out))

    assert code == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1

def test_multi_run_findings_count(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "multi_run.sarif", out=out))
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 2


# ── occurrence counter ────────────────────────────────────────────────────────

def test_duplicate_findings_get_different_occurrences(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "duplicate_findings.sarif", out=out))
    data = json.loads(out.read_text())
    occurrences = [f["occurrence"] for f in data["findings"]]
    assert occurrences == [0, 1, 2]

def test_duplicate_findings_get_different_swb_ids(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "duplicate_findings.sarif", out=out))
    data = json.loads(out.read_text())
    ids = [f["swb_id"] for f in data["findings"]]
    assert len(ids) == len(set(ids))


# ── provenance ────────────────────────────────────────────────────────────────

def test_provenance_tool_name(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out))
    data = json.loads(out.read_text())
    assert data["provenance"]["tool"] == "TestTool"

def test_provenance_no_git_flag(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, no_git=True))
    data = json.loads(out.read_text())
    assert data["provenance"]["commit"] == "0" * 40


# ── code snippets ─────────────────────────────────────────────────────────────

def test_code_is_null_without_repo_root(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=None))
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None

def test_code_is_null_with_none_policy(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out,
                repo_root=DATA, context_policy="none"))
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None

def test_code_snippet_extracted_with_repo_root(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=DATA, context_policy="line"))
    data = json.loads(out.read_text())
    code = data["findings"][0]["code"]
    assert code is not None
    assert code["lang"] == "python"
    assert "CWE-89" in code["snippet"]

def test_code_start_line_matches_finding(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=DATA, context_policy="line"))
    data = json.loads(out.read_text())
    code = data["findings"][0]["code"]
    assert code["start_line"] == 42

def test_code_lines_policy_expands_context(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out,
                repo_root=DATA, context_policy="lines", context_lines=5))
    data = json.loads(out.read_text())
    code = data["findings"][0]["code"]
    assert code["start_line"] < 42
    assert code["end_line"] > 42


# ── git info ──────────────────────────────────────────────────────────────────

def test_git_is_null_when_no_git_flag(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=DATA, no_git=True))
    data = json.loads(out.read_text())
    assert data["findings"][0]["git"] is None

def test_git_is_null_without_repo_root(tmp_path):
    out = tmp_path / "out.swbmeta.json"
    enrich(Args(VALID / "minimal.sarif", out=out, repo_root=None, no_git=False))
    data = json.loads(out.read_text())
    assert data["findings"][0]["git"] is None


# ── path traversal через uri (T-01) ──────────────────────────────────────────

def _record_git_calls(monkeypatch):
    """Подменяет _git; возвращает список перехваченных вызовов."""
    calls = []

    def fake_git(cwd, git_args):
        calls.append(git_args)
        return ""

    monkeypatch.setattr("swb_cli.commands.enrich._git", fake_git)
    return calls

def test_git_info_rejects_relative_traversal(tmp_path, monkeypatch, caplog):
    root = tmp_path / "repo"
    source_root = root
    root.mkdir()
    (tmp_path / "secret.py").write_text("TOP_SECRET = 1\n")
    calls = _record_git_calls(monkeypatch)
    with caplog.at_level(logging.WARNING):
        assert _get_git_info(root, source_root, "../secret.py", 1, None) is None
    assert calls == []
    assert "source root" in caplog.text

def test_git_info_rejects_absolute_uri_outside_root(tmp_path, monkeypatch, caplog):
    root = tmp_path / "repo"
    source_root = root
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("TOP_SECRET = 1\n")
    calls = _record_git_calls(monkeypatch)
    with caplog.at_level(logging.WARNING):
        assert _get_git_info(root, source_root, str(outside), 1, None) is None
    assert calls == []

def test_git_info_rejects_symlink_escaping_root(tmp_path, monkeypatch, caplog):
    root = tmp_path / "repo"
    source_root = root
    root.mkdir()
    secret = tmp_path / "secret.py"
    secret.write_text("TOP_SECRET = 1\n")
    (root / "link.py").symlink_to(secret)
    calls = _record_git_calls(monkeypatch)
    with caplog.at_level(logging.WARNING):
        assert _get_git_info(root, source_root, "link.py", 1, None) is None
    assert calls == []

def test_enrich_traversal_uris_get_null_code_and_warn(tmp_path, caplog):
    # SARIF с двумя вредоносными uri и одним легитимным: enrich не падает,
    # вредоносные находки получают code=None, легитимная обогащается как раньше
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.WARNING):
        code = enrich(Args(MALICIOUS / "path_traversal.sarif", out=out,
                           repo_root=DATA, context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    by_uri = {f["locator"]["uri"]: f for f in data["findings"]}
    assert by_uri["../../../../../../../../etc/passwd"]["code"] is None
    assert by_uri["/etc/passwd"]["code"] is None
    good = by_uri["src/db.py"]["code"]
    assert good is not None
    assert "CWE-89" in good["snippet"]
    assert "source root" in caplog.text


# ── лимит размера исходников (T-02) ──────────────────────────────────────────

def test_enrich_oversized_source_gets_null_code_and_warns(tmp_path, monkeypatch, caplog):
    # исходник крупнее лимита: enrich не падает, code=None, warning в stderr-лог
    monkeypatch.setenv("SWB_MAX_SOURCE_MB", "1")
    src = tmp_path / "src"
    src.mkdir()
    (src / "db.py").write_bytes(b"# huge\n" * 300_000)  # ~2 МБ > лимита в 1 МБ
    out = tmp_path / "out.swbmeta.json"
    with caplog.at_level(logging.WARNING):
        code = enrich(Args(VALID / "minimal.sarif", out=out,
                           repo_root=tmp_path, context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None
    assert "SWB_MAX_SOURCE_MB" in caplog.text



#── разрешение путей: source_root vs repo_root ───────────────────────────────
#
# source_root — источник истины для поиска исходников; finding-путь всегда
# резолвится относительно него, а не относительно
# repo_root. repo_root используется отдельно 
 
def _write_sarif(path: Path, uri: str, start_line: int = 1, rule_id: str = "CWE-89",
                  tool_name: str = "TestTool") -> None:
    path.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": "1.0", "rules": []}},
            "results": [{
                "ruleId": rule_id, "level": "error",
                "message": {"text": "finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start_line},
                }}],
            }],
        }],
    }))
 
 
def test_resolution_source_root_equals_repo_root(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("l1\nl2\nMARKER\nl4\nl5\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "src/main.py", start_line=3)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=root, source_root=root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    snippet = data["findings"][0]["code"]
    assert snippet is not None
    assert "MARKER" in snippet["snippet"]
 
 
def test_resolution_source_root_nested_in_repo_root(tmp_path):
    # repo_root/backend/src/foo/bar.py — source_root лежит глубже repo_root,
    # finding-путь относителен именно к source_root 
    repo_root = tmp_path / "project"
    source_root = repo_root / "backend" / "src"
    (source_root / "foo").mkdir(parents=True)
    (source_root / "foo" / "bar.py").write_text("l1\nMARKER\nl3\n")
 
    assert not (repo_root / "foo" / "bar.py").exists()
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "foo/bar.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=repo_root, source_root=source_root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    snippet = data["findings"][0]["code"]
    assert snippet is not None
    assert "MARKER" in snippet["snippet"]
 
 
def test_resolution_relative_path_nested_directories(tmp_path):
    root = tmp_path / "repo"
    (root / "a" / "b" / "c").mkdir(parents=True)
    (root / "a" / "b" / "c" / "deep.py").write_text("l1\nl2\nMARKER\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "a/b/c/deep.py", start_line=3)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=root, source_root=root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    assert "MARKER" in data["findings"][0]["code"]["snippet"]
 
 
def test_resolution_path_with_dot_slash_prefix(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("l1\nMARKER\nl3\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "./src/main.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=root, source_root=root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    assert "MARKER" in data["findings"][0]["code"]["snippet"]
 
 
def test_resolution_absolute_uri_within_source_root(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    target = root / "src" / "main.py"
    target.write_text("l1\nMARKER\nl3\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, str(target), start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=root, source_root=root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    snippet = data["findings"][0]["code"]
    assert snippet is not None
    assert "MARKER" in snippet["snippet"]
 
 
def test_resolution_missing_file_gives_null_code(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "src/does_not_exist.py", start_line=1)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=root, source_root=root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    assert data["findings"][0]["code"] is None
 
 
def test_resolution_exists_under_source_root_not_under_repo_root(tmp_path):
    # Ключевой сценарий из требований: файл физически существует только
    # относительно source_root; тот же относительный путь под repo_root
    # ничего не даёт. Раньше это приводило к тому, что enrich не находил
    # существующий на диске файл.
    repo_root = tmp_path / "project"
    source_root = repo_root / "backend" / "src"
    source_root.mkdir(parents=True)
    (source_root / "db.py").write_text("l1\nMARKER\nl3\n")
 
    assert not (repo_root / "db.py").exists()
    assert (source_root / "db.py").exists()
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "db.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=repo_root, source_root=source_root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    snippet = data["findings"][0]["code"]
    assert snippet is not None
    assert "MARKER" in snippet["snippet"]
 
 
def test_resolution_original_uri_preserved_regardless_of_root(tmp_path):
    # locator.uri должен оставаться исходным значением из finding'а, даже
    # когда effective_uri (после resolve_uri/normalize) отличается от него.
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("l1\nMARKER\nl3\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "./src/main.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    enrich(Args(sarif, out=out, repo_root=root, source_root=root,
                context_policy="line"))
    data = json.loads(out.read_text())
    assert data["findings"][0]["locator"]["uri"] == "./src/main.py"
 
 
def test_resolution_default_source_root_falls_back_to_repo_root(tmp_path):
    # Если --source-root явно не задан, а --repo-root задан, enrich.py по
    # умолчанию использует source_root = repo_root — файлы прямо под
    # repo_root по-прежнему должны находиться.
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("l1\nMARKER\nl3\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "src/main.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=root, source_root=None,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    assert "MARKER" in data["findings"][0]["code"]["snippet"]
 
 
def test_resolution_source_root_outside_repo_root_is_ignored(tmp_path):
    # enrich.py игнорирует --source-root, если он лежит вне --repo-root
    # и падает обратно на
    # repo_root как source_root.
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    (repo_root / "src" / "main.py").write_text("l1\nMARKER\nl3\n")
 
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "src/main.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=repo_root, source_root=outside_root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    # source_root вне repo_root проигнорирован -> используется repo_root,
    # файл всё ещё находится.
    assert "MARKER" in data["findings"][0]["code"]["snippet"]
 
 
def test_resolution_multiple_roots_norm_uri_and_snippet_both_correct(tmp_path):
    # Одновременная проверка двух разных ролей repo_root/source_root:
    # snippet читается относительно source_root (глубже repo_root), а
    # norm_uri в locator остаётся детерминированным путём, не завязанным
    # на случайное совпадение с repo_root.
    repo_root = tmp_path / "project"
    source_root = repo_root / "backend" / "src"
    (source_root / "pkg").mkdir(parents=True)
    (source_root / "pkg" / "mod.py").write_text("l1\nMARKER\nl3\n")
 
    sarif = tmp_path / "report.sarif"
    _write_sarif(sarif, "pkg/mod.py", start_line=2)
    out = tmp_path / "out.swbmeta.json"
 
    code = enrich(Args(sarif, out=out, repo_root=repo_root, source_root=source_root,
                        context_policy="line"))
    assert code == 0
    data = json.loads(out.read_text())
    finding = data["findings"][0]
    assert "MARKER" in finding["code"]["snippet"]
    assert finding["locator"]["norm_uri"] == "pkg/mod.py"