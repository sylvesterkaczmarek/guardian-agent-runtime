from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from collections.abc import Iterable, Mapping
from typing import Any

from guardian_runtime.types import ActionRequest


class CapabilityError(ValueError):
    pass


_ALLOWED_CONSTRAINT_KEYS = {"enum", "min", "max", "prefix", "forbid", "required"}


@dataclass(frozen=True)
class Capability:
    capability_id: str
    subject: str
    tool: str
    action: str
    resource: str = "*"
    session: str = "*"
    constraints: Mapping[str, Any] = field(default_factory=dict)
    prohibited_params: tuple[str, ...] = ()
    purpose: tuple[str, ...] = ()
    not_before: int = 0
    expires_at: int = 2**63 - 1
    max_invocations: int = 1_000_000
    delegation_depth: int = 0
    parent_id: str | None = None


def _has_wildcard(pattern: str) -> bool:
    return any(char in pattern for char in "*?[")


def _scope_pattern_subset(child: str, parent: str) -> bool:
    """Conservative glob-language subset check.

    Exact child values may narrow a wildcard parent. A child wildcard is accepted only
    when it is identical to the parent or the parent is the universal wildcard. This is
    intentionally conservative because accepting an uncertain delegation is worse than
    rejecting a legitimate one.
    """

    if child == parent:
        return True
    if parent == "*":
        return True
    if _has_wildcard(child):
        return False
    return fnmatch.fnmatchcase(child, parent)


def _validate_constraint(name: str, constraint: Any) -> None:
    if not isinstance(constraint, dict):
        return
    unknown = set(constraint) - _ALLOWED_CONSTRAINT_KEYS
    if unknown:
        raise CapabilityError(f"unknown constraint keys for {name}: {sorted(unknown)}")
    if "enum" in constraint and not isinstance(constraint["enum"], (list, tuple)):
        raise CapabilityError(f"enum constraint for {name} must be a sequence")
    if "forbid" in constraint and not isinstance(constraint["forbid"], (list, tuple)):
        raise CapabilityError(f"forbid constraint for {name} must be a sequence")
    if "prefix" in constraint and not isinstance(constraint["prefix"], str):
        raise CapabilityError(f"prefix constraint for {name} must be a string")
    if "required" in constraint and not isinstance(constraint["required"], bool):
        raise CapabilityError(f"required constraint for {name} must be boolean")
    for bound in ("min", "max"):
        if bound in constraint and (
            not isinstance(constraint[bound], (int, float)) or isinstance(constraint[bound], bool)
        ):
            raise CapabilityError(f"{bound} constraint for {name} must be numeric")
    if "min" in constraint and "max" in constraint and constraint["min"] > constraint["max"]:
        raise CapabilityError(f"invalid numeric bounds for {name}")


def _validate_capability(capability: Capability) -> None:
    for field_name in ("capability_id", "subject", "tool", "action", "resource", "session"):
        value = getattr(capability, field_name)
        if not isinstance(value, str) or not value:
            raise CapabilityError(f"{field_name} must be a non-empty string")
    if capability.not_before < 0 or capability.expires_at <= capability.not_before:
        raise CapabilityError("capability validity interval is invalid")
    if capability.max_invocations < 0:
        raise CapabilityError("max_invocations must be non-negative")
    if capability.delegation_depth < 0:
        raise CapabilityError("delegation_depth must be non-negative")
    if not all(isinstance(item, str) and item for item in capability.prohibited_params):
        raise CapabilityError("prohibited_params must contain non-empty strings")
    if not all(isinstance(item, str) and item for item in capability.purpose):
        raise CapabilityError("purpose must contain non-empty strings")
    if len(set(capability.prohibited_params)) != len(capability.prohibited_params):
        raise CapabilityError("prohibited_params contains duplicates")
    if len(set(capability.purpose)) != len(capability.purpose):
        raise CapabilityError("purpose contains duplicates")
    if capability.parent_id is not None and (not isinstance(capability.parent_id, str) or not capability.parent_id):
        raise CapabilityError("parent_id must be a non-empty string when supplied")
    if not isinstance(capability.constraints, Mapping):
        raise CapabilityError("constraints must be a mapping")
    overlap = set(capability.constraints) & set(capability.prohibited_params)
    if overlap:
        raise CapabilityError(f"parameters cannot be both allowed and prohibited: {sorted(overlap)}")
    for name, constraint in capability.constraints.items():
        if not isinstance(name, str) or not name:
            raise CapabilityError("constraint names must be non-empty strings")
        _validate_constraint(name, constraint)


def _value_satisfies(value: Any, constraint: Any) -> bool:
    if not isinstance(constraint, dict):
        return value == constraint
    if "enum" in constraint and value not in constraint["enum"]:
        return False
    if "min" in constraint:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < constraint["min"]:
            return False
    if "max" in constraint:
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value > constraint["max"]:
            return False
    if "prefix" in constraint:
        if not isinstance(value, str) or not value.startswith(str(constraint["prefix"])):
            return False
    if "forbid" in constraint and value in constraint["forbid"]:
        return False
    return True


def _constraint_subset(child: Any, parent: Any) -> bool:
    """Return True only when every value accepted by child is accepted by parent."""

    if not isinstance(parent, dict):
        return child == parent

    parent_required = bool(parent.get("required", False))
    if not isinstance(child, dict):
        # A scalar constraint does not require the parameter to be present, so it cannot
        # preserve a parent's presence requirement.
        return not parent_required and _value_satisfies(child, parent)

    if parent_required and not bool(child.get("required", False)):
        return False

    if "enum" in parent:
        if "enum" in child:
            child_enum = child["enum"]
            if not child_enum or not all(value in parent["enum"] for value in child_enum):
                return False
        elif any(key in child for key in ("min", "max", "prefix")):
            return False
        else:
            # Without an enum or an exact scalar, the child could accept values outside
            # the parent's finite set.
            return False

    if "min" in parent and child.get("min", float("-inf")) < parent["min"]:
        return False
    if "max" in parent and child.get("max", float("inf")) > parent["max"]:
        return False
    if "prefix" in parent:
        child_prefix = child.get("prefix")
        if child_prefix is None or not str(child_prefix).startswith(str(parent["prefix"])):
            return False
    if "forbid" in parent and not all(
        value in child.get("forbid", []) for value in parent["forbid"]
    ):
        return False
    return True


def capability_is_subset(child: Capability, parent: Capability) -> bool:
    _validate_capability(child)
    _validate_capability(parent)
    if child.subject != parent.subject:
        return False
    for child_value, parent_pattern in (
        (child.session, parent.session),
        (child.tool, parent.tool),
        (child.action, parent.action),
        (child.resource, parent.resource),
    ):
        if not _scope_pattern_subset(child_value, parent_pattern):
            return False
    if child.not_before < parent.not_before or child.expires_at > parent.expires_at:
        return False
    if child.max_invocations > parent.max_invocations:
        return False
    if parent.delegation_depth <= 0 or child.delegation_depth >= parent.delegation_depth:
        return False

    # Empty purpose means unrestricted. A restricted parent therefore requires an
    # explicitly restricted child.
    if parent.purpose:
        if not child.purpose or not set(child.purpose).issubset(set(parent.purpose)):
            return False

    # A child cannot make a parent-prohibited parameter available again.
    if not set(parent.prohibited_params).issubset(set(child.prohibited_params)):
        return False

    # Any required parent parameter must remain required. Optional parent parameters
    # may be omitted entirely by the child, which is a narrowing because undeclared
    # parameters are rejected by validation.
    for key, parent_constraint in parent.constraints.items():
        required = isinstance(parent_constraint, dict) and bool(parent_constraint.get("required", False))
        if key not in child.constraints:
            if required:
                return False
            continue
        if not _constraint_subset(child.constraints[key], parent_constraint):
            return False

    # A child may not introduce a parameter that the parent never authorized.
    for key in child.constraints:
        if key not in parent.constraints:
            return False
    return True


class CapabilityStore:
    def __init__(self, capabilities: Iterable[Capability] = ()) -> None:
        self._caps: dict[str, Capability] = {}
        self._revoked: set[str] = set()
        self._used_nonces: dict[str, set[str]] = {}
        self._invocations: dict[str, int] = {}
        for capability in capabilities:
            self.add(capability)

    def _lineage(self, capability: Capability) -> tuple[Capability, ...]:
        lineage: list[Capability] = [capability]
        seen = {capability.capability_id}
        current = capability
        while current.parent_id is not None:
            if current.parent_id in seen:
                raise CapabilityError("capability delegation cycle detected")
            parent = self._caps.get(current.parent_id)
            if parent is None:
                raise CapabilityError("delegation parent not found")
            if not capability_is_subset(current, parent):
                raise CapabilityError("delegated capability increases authority")
            lineage.append(parent)
            seen.add(parent.capability_id)
            current = parent
        return tuple(lineage)

    def add(self, capability: Capability) -> None:
        _validate_capability(capability)
        if capability.capability_id in self._caps:
            raise CapabilityError("capability id already exists")
        if capability.parent_id:
            parent = self._caps.get(capability.parent_id)
            if parent is None:
                raise CapabilityError("delegation parent not found")
            if parent.capability_id in self._revoked:
                raise CapabilityError("cannot delegate from a revoked capability")
            if not capability_is_subset(capability, parent):
                raise CapabilityError("delegated capability increases authority")
        self._caps[capability.capability_id] = capability
        # Validate the full lineage after insertion; remove it again if the lineage is invalid.
        try:
            self._lineage(capability)
        except Exception:
            self._caps.pop(capability.capability_id, None)
            raise

    def revoke(self, capability_id: str) -> None:
        if capability_id not in self._caps:
            raise CapabilityError("unknown capability")
        self._revoked.add(capability_id)

    def get(self, capability_id: str) -> Capability | None:
        return self._caps.get(capability_id)

    def status(self, capability_id: str, now: int) -> tuple[bool, str]:
        cap = self._caps.get(capability_id)
        if cap is None:
            return False, "unknown capability"
        try:
            lineage = self._lineage(cap)
        except CapabilityError as exc:
            return False, str(exc)
        for item in lineage:
            if item.capability_id in self._revoked:
                if item.capability_id == cap.capability_id:
                    return False, "capability revoked"
                return False, f"delegation ancestor revoked: {item.capability_id}"
            if now < item.not_before:
                return False, f"capability not yet valid: {item.capability_id}"
            if now >= item.expires_at:
                return False, f"capability expired: {item.capability_id}"
        return True, "capability active"

    def validate(self, request: ActionRequest, now: int, *, consume: bool = True) -> tuple[bool, str]:
        cap = self._caps.get(request.capability_id)
        if cap is None:
            return False, "unknown capability"
        active, reason = self.status(cap.capability_id, now)
        if not active:
            return False, reason

        try:
            lineage = self._lineage(cap)
        except CapabilityError as exc:
            return False, str(exc)

        if request.subject != cap.subject:
            return False, "capability subject mismatch"
        if not fnmatch.fnmatchcase(request.session_id, cap.session):
            return False, "session outside capability"
        if not fnmatch.fnmatchcase(request.tool, cap.tool):
            return False, "tool outside capability"
        if not fnmatch.fnmatchcase(request.action, cap.action):
            return False, "action outside capability"
        if not fnmatch.fnmatchcase(request.resource or "", cap.resource):
            return False, "resource outside capability"
        if cap.purpose and request.purpose not in cap.purpose:
            return False, "purpose outside capability"

        for item in lineage:
            if self._invocations.get(item.capability_id, 0) >= item.max_invocations:
                if item.capability_id == cap.capability_id:
                    return False, "capability invocation limit reached"
                return False, f"delegation ancestor invocation limit reached: {item.capability_id}"
            if request.nonce in self._used_nonces.setdefault(item.capability_id, set()):
                return False, f"replayed nonce in capability lineage: {item.capability_id}"

        prohibited = set(cap.prohibited_params)
        for key, value in request.params.items():
            if key in prohibited:
                return False, f"prohibited parameter: {key}"
            if key not in cap.constraints:
                return False, f"undeclared parameter: {key}"
            if not _value_satisfies(value, cap.constraints[key]):
                return False, f"parameter outside capability: {key}"
        for key, constraint in cap.constraints.items():
            if isinstance(constraint, dict) and constraint.get("required") and key not in request.params:
                return False, f"missing required parameter: {key}"

        if consume:
            for item in lineage:
                self._used_nonces.setdefault(item.capability_id, set()).add(request.nonce)
                self._invocations[item.capability_id] = self._invocations.get(item.capability_id, 0) + 1
        return True, "capability valid"

    def clone(self) -> "CapabilityStore":
        clone = CapabilityStore(self._caps.values())
        clone._revoked = set(self._revoked)
        clone._used_nonces = {key: set(values) for key, values in self._used_nonces.items()}
        clone._invocations = dict(self._invocations)
        return clone

    def reset_usage(self) -> None:
        self._used_nonces.clear()
        self._invocations.clear()

    def invocation_count(self, capability_id: str) -> int:
        return self._invocations.get(capability_id, 0)


def capability_from_dict(data: Mapping[str, Any]) -> Capability:
    payload = dict(data)
    for field_name in ("purpose", "prohibited_params"):
        raw = payload.get(field_name, ())
        if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
            raise CapabilityError(f"{field_name} must be a sequence of strings")
        payload[field_name] = tuple(raw)
    capability = Capability(**payload)
    _validate_capability(capability)
    return capability
