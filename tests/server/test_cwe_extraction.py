"""Извлечение CWE из правил SARIF — `ingest._extract_cwes`.

Формат тега у анализаторов разный, и прежняя реализация умела ровно один
из них. Проверяется:
  (а) формат Semgrep (`CWE-89: …`) — прежнее поведение не сломано;
  (б) формат CodeQL (`external/cwe/cwe-020`) — тег не начинается с «cwe»,
      из-за чего `re.match` не находил его никогда: на реальном ране ndpi
      извлекалось 0 CWE из 39 находок;
  (в) ведущие нули: `cwe-089` → `CWE-89`, иначе значение не склеивается
      ни с фильтром `?cwe=`, ни с агрегацией `by=cwe`;
  (г) несколько CWE на правило — CodeQL перечисляет по 2-5, прежняя
      реализация возвращала первый попавшийся и теряла остальные;
  (д) порядок анализатора сохраняется, дубли снимаются;
  (е) сквозной путь через `ingest()`: в находку попадают и основной CWE,
      и полный список.
"""
from __future__ import annotations

import json

import pytest

import swb_server.ingest as ingest_mod
from swb_server.ingest import _extract_cwes


def _sarif(driver: dict, results: list[dict] | None = None) -> bytes:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results or []}],
    }).encode()


# ── (а)-(в) форматы тегов ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "tags,expected",
    [
        # Semgrep: тег начинается с идентификатора, дальше описание
        (["CWE-89: Improper Neutralization", "security"], ["CWE-89"]),
        (["CWE-798", "security"], ["CWE-798"]),
        # CodeQL: идентификатор в конце пути — сюда `re.match` не добирался
        (["external/cwe/cwe-209", "security"], ["CWE-209"]),
        # ведущие нули снимаются
        (["external/cwe/cwe-020"], ["CWE-20"]),
        (["external/cwe/cwe-089"], ["CWE-89"]),
        # регистр не важен
        (["EXTERNAL/CWE/CWE-79"], ["CWE-79"]),
        # тегов с CWE нет вовсе — Bandit, запросы CodeQL про качество кода
        (["security", "correctness", "maintainability"], []),
        ([], []),
    ],
)
def test_tag_formats(tags, expected):
    assert _extract_cwes("some-rule", tags) == expected


def test_zero_padded_and_plain_form_collapse():
    """`cwe-020` и `CWE-20` — один и тот же CWE, а не два разных."""
    assert _extract_cwes("r", ["external/cwe/cwe-020", "CWE-20"]) == ["CWE-20"]


# ── (г)-(д) несколько CWE ──────────────────────────────────────────────────


def test_all_cwes_returned_not_just_the_first():
    """py/path-injection в CodeQL несёт четыре CWE — терять три нельзя."""
    tags = [
        "external/cwe/cwe-022",
        "external/cwe/cwe-023",
        "external/cwe/cwe-036",
        "external/cwe/cwe-073",
        "security",
    ]
    assert _extract_cwes("py/path-injection", tags) == [
        "CWE-22", "CWE-23", "CWE-36", "CWE-73",
    ]


def test_analyzer_order_is_preserved():
    """Порядок задаёт анализатор: первым идёт тот CWE, на который нацелено
    правило. Сортировать по номеру нельзя — основной CWE не всегда меньший."""
    assert _extract_cwes("r", ["external/cwe/cwe-497", "external/cwe/cwe-209"]) == [
        "CWE-497", "CWE-209",
    ]


def test_duplicates_removed():
    assert _extract_cwes("r", ["CWE-79", "external/cwe/cwe-079", "CWE-79: XSS"]) == ["CWE-79"]


# ── идентификатор правила как запасной источник ────────────────────────────


def test_falls_back_to_rule_id_when_tags_have_none():
    """Прежнее поведение: у правил без тегов CWE иногда сидит в самом id."""
    assert _extract_cwes("CWE-89", []) == ["CWE-89"]


def test_tags_come_before_rule_id():
    assert _extract_cwes("CWE-1", ["CWE-79"]) == ["CWE-79", "CWE-1"]


# ── (е) сквозь ingest() ────────────────────────────────────────────────────


def _driver_with(tags: list[str]) -> dict:
    return {
        "name": "CodeQL", "version": "2.26.4",
        "rules": [{
            "id": "py/path-injection",
            "properties": {"tags": tags},
            "defaultConfiguration": {"level": "error"},
        }],
    }


def test_ingest_puts_all_cwes_on_the_rule():
    tags = ["external/cwe/cwe-022", "external/cwe/cwe-023", "security"]
    out = ingest_mod.ingest(_sarif(_driver_with(tags)), {"schema": "swbmeta/v3", "findings": []})
    assert out["rules"]["py/path-injection"]["cwes"] == ["CWE-22", "CWE-23"]


def test_ingest_finding_carries_primary_cwe_and_full_list():
    tags = ["external/cwe/cwe-022", "external/cwe/cwe-023", "security"]
    results = [{
        "ruleId": "py/path-injection",
        "level": "error",
        "message": {"text": "finding"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.py"},
            "region": {"startLine": 1},
        }}],
    }]
    meta = {"schema": "swbmeta/v3", "findings": [{
        "swb_id": "sw2:t:abc:0",
        "occurrence": 0,
        "locator": {"run": 0, "result": 0, "rule_id": "py/path-injection",
                    "uri": "src/a.py", "norm_uri": "src/a.py", "region": {"start_line": 1}},
        "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": "py/path-injection"},
    }]}
    finding = ingest_mod.ingest(_sarif(_driver_with(tags), results), meta)["findings"][0]
    assert finding["cwe"] == "CWE-22"
    assert finding["cwes"] == ["CWE-22", "CWE-23"]


def test_ingest_finding_without_cwe_gets_none_not_empty_string():
    """Отсутствие CWE — это None, а не пустая строка: на `cwe` стоит
    coalesce в агрегации, и пустая строка стала бы отдельной группой."""
    results = [{
        "ruleId": "py/unused-import",
        "level": "note",
        "message": {"text": "finding"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.py"},
            "region": {"startLine": 1},
        }}],
    }]
    driver = {"name": "CodeQL", "version": "2.26.4", "rules": [{
        "id": "py/unused-import", "properties": {"tags": ["maintainability"]},
    }]}
    meta = {"schema": "swbmeta/v3", "findings": [{
        "swb_id": "sw2:t:abc:0",
        "occurrence": 0,
        "locator": {"run": 0, "result": 0, "rule_id": "py/unused-import",
                    "uri": "src/a.py", "norm_uri": "src/a.py", "region": {"start_line": 1}},
        "fingerprints": {"algo": "swb-fp/2", "level": "tool", "rule": "py/unused-import"},
    }]}
    finding = ingest_mod.ingest(_sarif(driver, results), meta)["findings"][0]
    assert finding["cwe"] is None
    assert finding["cwes"] == []
