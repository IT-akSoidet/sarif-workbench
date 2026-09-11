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

from datetime import datetime
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from swb_contract.fstec import (
    LEVELS,
    METHODOLOGY,
    TABLE_1,
    ComponentType,
    Exploitation,
    IndicatorSpec,
    PerimeterExposure,
    VulnerableShare,
)

from ..criticality import recompute_project
from ..db import get_db
from ..models import Project, SystemProfile

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


# ── Профиль информационной системы ─────────────────────────────────────────
#
# Показатели K, L и P описывают систему, а не находку, и в SARIF их нет по
# природе: анализатор видит исходный код, а не развёрнутый компонент. П. 8в
# методики берёт их из инвентаризации, поэтому заполняются вручную — один раз
# на проект, а не на каждую находку.

# Поле профиля → перечисление контракта, значения которого оно принимает.
_PROFILE_FIELDS: dict[str, type[Enum]] = {
    "component_type": ComponentType,
    "vulnerable_share": VulnerableShare,
    "perimeter_exposure": PerimeterExposure,
}


def _profile_to_dict(profile: SystemProfile | None) -> dict:
    """Профиль плюс перечень незаполненных полей.

    Пустое поле — это «не задано», а не ноль: находка с таким профилем уходит
    в «требует оценки». Список `missing` тут для того, чтобы интерфейс мог
    сказать, чего именно не хватает, не сверяя поля сам.
    """
    values = {
        field: getattr(profile, field, None) if profile else None for field in _PROFILE_FIELDS
    }
    return {
        **values,
        "missing": [field for field, value in values.items() if value is None],
        "complete": all(values.values()),
        "updated_by": profile.updated_by if profile else None,
        "updated_at": profile.updated_at.isoformat() if profile and profile.updated_at else None,
    }


def _validate(body: dict) -> dict[str, str | None]:
    """Значения из тела запроса, проверенные по перечислениям контракта.

    Неизвестное значение — 400, а не тихая запись: строка, не совпадающая с
    перечислением, позже уронит расчёт где-то далеко от места ошибки, и
    находка будет выглядеть недооценённой без объяснения. Явный `null`
    очищает поле — так профиль можно вернуть в «не заполнено».
    """
    # `updated_by` — не показатель методики, а подпись под решением, но
    # приходит тем же телом и в список неизвестных попадать не должен.
    unknown = set(body) - set(_PROFILE_FIELDS) - {"updated_by"}
    if unknown:
        raise HTTPException(400, {
            "error": "bad_request",
            "message": f"неизвестные поля профиля: {sorted(unknown)}",
        })

    cleaned: dict[str, str | None] = {}
    for field, enum_cls in _PROFILE_FIELDS.items():
        if field not in body:
            continue
        value = body[field]
        if value is None:
            cleaned[field] = None
            continue
        allowed = [member.value for member in enum_cls]
        if value not in allowed:
            raise HTTPException(400, {
                "error": "bad_request",
                "message": f"{field}: недопустимое значение {value!r}; допустимы {allowed}",
            })
        cleaned[field] = value
    return cleaned


@router.get("/projects/{project_id}/fstec-profile")
def get_profile(project_id: str, db: Session = Depends(get_db)) -> dict:
    if not db.get(Project, project_id):
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})
    return _profile_to_dict(db.get(SystemProfile, project_id))


@router.put("/projects/{project_id}/fstec-profile")
def set_profile(project_id: str, body: dict, db: Session = Depends(get_db)) -> dict:
    """Записать профиль и пересчитать находки проекта.

    Пересчёт здесь обязателен по п. 19: K, L и P входят в формулу, и после
    их изменения прежние уровни критичности недействительны.
    """
    if not db.get(Project, project_id):
        raise HTTPException(404, {"error": "not_found", "message": "Project not found"})

    cleaned = _validate(body)
    profile = db.get(SystemProfile, project_id) or SystemProfile(project_id=project_id)
    for field, value in cleaned.items():
        setattr(profile, field, value)
    # Column[T]-vs-T false positive (same class as verdicts.py:123, T-54)
    profile.updated_by = body.get("updated_by") or "human"  # type: ignore[assignment]
    profile.updated_at = datetime.utcnow()  # type: ignore[assignment]
    db.add(profile)
    db.flush()

    stats = recompute_project(db, project_id)
    db.commit()

    return {**_profile_to_dict(profile), "recomputed": stats}
