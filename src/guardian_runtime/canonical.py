from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any

from guardian_runtime.types import ActionRequest


class CanonicalizationError(ValueError):
    pass


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite numeric value")
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError("strings must contain valid Unicode scalar values") from exc
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            str(value)
        except ValueError as exc:
            raise CanonicalizationError("integer exceeds the interpreter's JSON digit limit") from exc
        return value
    if value is None or isinstance(value, bool):
        return value
    raise CanonicalizationError(f"unsupported scalar type: {type(value).__name__}")


def normalize_json(value: Any, *, max_depth: int = 128) -> Any:
    return _normalize_json(value, depth=0, max_depth=max_depth)


def _normalize_json(value: Any, *, depth: int, max_depth: int) -> Any:
    if depth > max_depth:
        raise CanonicalizationError(f"JSON nesting exceeds {max_depth} levels")
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if not all(isinstance(key, str) and key for key in keys):
            raise CanonicalizationError("object keys must be non-empty strings")
        normalized: dict[str, Any] = {}
        for key in sorted(keys):
            _normalize_scalar(key)
            normalized[key] = _normalize_json(value[key], depth=depth + 1, max_depth=max_depth)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, depth=depth + 1, max_depth=max_depth) for item in value]
    return _normalize_scalar(value)


def canonical_json(value: Any) -> bytes:
    normalized = normalize_json(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def canonicalize_resource(resource: str) -> str:
    if not isinstance(resource, str):
        raise CanonicalizationError("resource must be a string")
    _normalize_scalar(resource)
    if not resource:
        return ""
    if "\\" in resource:
        raise CanonicalizationError("backslashes are not permitted in resources")
    path = PurePosixPath(resource)
    if any(part in {"..", "."} for part in path.parts):
        raise CanonicalizationError("relative resource segments are not permitted")
    normalized = str(path)
    if resource.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def canonicalize_request(request: ActionRequest) -> ActionRequest:
    for name in ("subject", "session_id", "tool", "action", "capability_id", "nonce"):
        value = getattr(request, name)
        if not isinstance(value, str) or not value.strip():
            raise CanonicalizationError(f"{name} must be a non-empty string")
        if value != value.strip():
            raise CanonicalizationError(f"{name} contains ambiguous surrounding whitespace")
        _normalize_scalar(value)

    if not isinstance(request.purpose, str):
        raise CanonicalizationError("purpose must be a string")
    if request.purpose != request.purpose.strip():
        raise CanonicalizationError("purpose contains ambiguous surrounding whitespace")
    _normalize_scalar(request.purpose)
    if not isinstance(request.params, Mapping) or not isinstance(request.context, Mapping):
        raise CanonicalizationError("params and context must be mappings")
    if request.observed_state_version is not None and (
        not isinstance(request.observed_state_version, int)
        or isinstance(request.observed_state_version, bool)
        or request.observed_state_version < 0
    ):
        raise CanonicalizationError("observed_state_version must be a non-negative integer")

    tool = request.tool.lower()
    action = request.action.lower()
    if tool != request.tool or action != request.action:
        raise CanonicalizationError("tool and action identifiers must already be canonical lowercase")

    params = normalize_json(request.params, max_depth=64)
    context = normalize_json(request.context, max_depth=64)
    resource = canonicalize_resource(request.resource)

    return replace(request, params=params, context=context, resource=resource)
