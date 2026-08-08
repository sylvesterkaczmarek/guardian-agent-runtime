from __future__ import annotations

import json
from typing import Any


class DuplicateJSONKeyError(ValueError):
    """Raised when JSON contains an ambiguous duplicate object key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def loads_unique(text: str) -> Any:
    """Parse JSON while rejecting duplicate object keys at every nesting level."""

    return json.loads(text, object_pairs_hook=_unique_object)
