"""Справочные данные методики ФСТЭК для интерфейса.

Интерфейсу нужны варианты выпадающих списков — строки таблицы 1 — и подписи
уровней таблицы 2. Отдавать их из контракта, а не переписывать в вебе руками:
в проекте уже есть ручная синхронизация `web/src/lib/severity.ts` с
`swb_contract/severity.py`, и там же стоит комментарий о том, что ничто не
связывает две копии, кроме внимательности. Второй раз это повторять не надо —
тем более для нормативных значений, расхождение в которых меняет уровень
критичности в отчёте регулятору.
"""
from __future__ import annotations

from fastapi import APIRouter

from swb_contract.fstec import (
    LEVELS,
    METHODOLOGY,
    TABLE_1,
    Exploitation,
    IndicatorSpec,
)

router = APIRouter(prefix="/api/v1")

# Показатель E интерфейс не спрашивает: для находки статического анализа в
# собственном коде записи об эксплуатации не существует, и значение всегда
# «отсутствуют сведения». Отдаётся отдельно — чтобы это решение было видно,
# а не выглядело пропуском.
_FIXED_EXPLOITATION = Exploitation.NO_INFORMATION


def _indicator(spec: IndicatorSpec) -> dict:
    return {
        "symbol": spec.symbol,
        "title": spec.title,
        "weight": spec.weight,
        "values": [
            {
                "value": value.value,
                "label": item.label,
                "score": item.score,
                # произведение из последнего столбца таблицы 1 — показывается
                # рядом с вариантом, чтобы выбор был осознанным
                "weighted": round(spec.weight * item.score, 4),
            }
            for value, item in spec.values.items()
        ],
    }


@router.get("/fstec/indicators")
def get_indicators() -> dict:
    """Таблицы 1 и 2 методики в виде, пригодном для построения форм."""
    return {
        "methodology": METHODOLOGY,
        "formula": "V = I_cvss × I_infr × (I_at + I_imp)",
        "indicators": {symbol: _indicator(spec) for symbol, spec in TABLE_1.items()},
        "levels": [
            {
                "key": level.key,
                "label": level.label,
                # срок устранения п. 21 — текстом, как в методике: перевод
                # «до 4 месяцев» в число дней уже допущение, а не норма
                "remediation": level.remediation,
                "min_value": level.min_value,
                "min_inclusive": level.inclusive,
            }
            for level in LEVELS
        ],
        "exploitation_fixed": {
            "value": _FIXED_EXPLOITATION.value,
            "label": TABLE_1["E"].values[_FIXED_EXPLOITATION].label,
            "reason": (
                "Для находки статического анализа в собственном коде записи "
                "об эксплуатации не существует — показатель не запрашивается."
            ),
        },
    }
