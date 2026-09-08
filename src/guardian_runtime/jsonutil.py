from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_DEPTH = 128


class DuplicateJSONKeyError(ValueError):
    """Raised when JSON contains an ambiguous duplicate object key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON numbers must be finite")
    return parsed


def _reject_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON numeric constant: {value}")


def loads_unique(text: str) -> Any:
    """Parse finite JSON with unique keys and a version-independent nesting limit."""

    try:
        result = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the parser limit") from exc
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return result
