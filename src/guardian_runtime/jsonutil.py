from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


MAX_JSON_DEPTH = 128
MAX_JSON_BYTES = 32 * 1024 * 1024


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

    if not isinstance(text, str):
        raise ValueError("JSON input must be text")
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("JSON input must be valid UTF-8 text") from exc
    if encoded_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_BYTES} bytes")
    # Check lexical nesting before allocating decoder structures. Quoted brackets
    # and escaped quotes are data, not nesting. json.loads still validates grammar.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        elif char in "]}":
            depth -= 1
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


def read_json_file(path: str | Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Read one bounded UTF-8 verifier input without an unbounded read_text call."""
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_JSON_BYTES:
        raise ValueError("JSON byte limit is invalid")
    with Path(path).open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"JSON input exceeds {max_bytes} bytes")
    return loads_unique(raw.decode("utf-8"))
