from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Mapping
from typing import Any

import yaml

from guardian_runtime.canonical import CanonicalizationError, canonicalize_resource
from guardian_runtime.types import ActionRequest, RuntimeState
from guardian_runtime.yamlutil import load_yaml_unique


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class RateLimit:
    max_calls: int
    window_seconds: int


@dataclass(frozen=True)
class ResourceBudget:
    key: str
    cost_param: str
    max_total: float


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    effect: str
    subject: str = "*"
    session: str = "*"
    tool: str = "*"
    action: str = "*"
    resource: str = "*"
    param_constraints: Mapping[str, Any] = field(default_factory=dict)
    state_constraints: Mapping[str, Any] = field(default_factory=dict)
    purpose: tuple[str, ...] = ()
    not_before: int | None = None
    expires_at: int | None = None
    rate_limit: RateLimit | None = None
    forbidden_after: tuple[str, ...] = ()
    separation_of_duty_after: tuple[str, ...] = ()
    resource_budget: ResourceBudget | None = None


@dataclass(frozen=True)
class EmergencyStop:
    state_key: str
    equals: Any
    allow_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    version: str
    default: str
    rules: tuple[PolicyRule, ...]
    emergency_stop: EmergencyStop | None = None


@dataclass
class PolicyRuntimeState:
    rule_hits: dict[str, list[int]] = field(default_factory=dict)
    authorization_history: list[tuple[int, str, str, str]] = field(default_factory=list)
    resource_usage: dict[str, float] = field(default_factory=dict)

    def clone(self) -> "PolicyRuntimeState":
        return PolicyRuntimeState(
            rule_hits={key: list(values) for key, values in self.rule_hits.items()},
            authorization_history=list(self.authorization_history),
            resource_usage=dict(self.resource_usage),
        )


_ALLOWED_TOP_LEVEL = {"version", "default", "rules", "emergency_stop"}
_ALLOWED_RULE_KEYS = {
    "id",
    "effect",
    "subject",
    "session",
    "tool",
    "action",
    "resource",
    "params",
    "state",
    "purpose",
    "not_before",
    "expires_at",
    "rate_limit",
    "forbidden_after",
    "separation_of_duty_after",
    "resource_budget",
}
_ALLOWED_CONSTRAINT_KEYS = {
    "eq",
    "neq",
    "in",
    "not_in",
    "min",
    "max",
    "prefix",
    "canonical_prefix",
    "canonical_resource",
    "required",
}


def _validate_constraint(name: str, constraint: Any) -> None:
    if not isinstance(constraint, dict):
        return
    unknown = set(constraint) - _ALLOWED_CONSTRAINT_KEYS
    if unknown:
        raise PolicyError(f"unknown constraint keys for {name}: {sorted(unknown)}")
    if "required" in constraint and not isinstance(constraint["required"], bool):
        raise PolicyError(f"required constraint for {name} must be boolean")
    for collection_key in ("in", "not_in"):
        if collection_key in constraint and not isinstance(constraint[collection_key], (list, tuple)):
            raise PolicyError(f"{collection_key} constraint for {name} must be a sequence")
    if "prefix" in constraint and not isinstance(constraint["prefix"], str):
        raise PolicyError(f"prefix constraint for {name} must be a string")
    if "canonical_prefix" in constraint and not isinstance(constraint["canonical_prefix"], str):
        raise PolicyError(f"canonical_prefix constraint for {name} must be a string")
    if "canonical_resource" in constraint and not isinstance(constraint["canonical_resource"], bool):
        raise PolicyError(f"canonical_resource constraint for {name} must be boolean")
    for bound in ("min", "max"):
        if bound in constraint and (
            not isinstance(constraint[bound], (int, float)) or isinstance(constraint[bound], bool)
        ):
            raise PolicyError(f"{bound} constraint for {name} must be numeric")
    if "min" in constraint and "max" in constraint and constraint["min"] > constraint["max"]:
        raise PolicyError(f"invalid numeric bounds for {name}")


def _matches_constraint(value: Any, constraint: Any) -> bool:
    if not isinstance(constraint, dict):
        return value == constraint
    if "eq" in constraint and value != constraint["eq"]:
        return False
    if "neq" in constraint and value == constraint["neq"]:
        return False
    if "in" in constraint and value not in constraint["in"]:
        return False
    if "not_in" in constraint and value in constraint["not_in"]:
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
    if constraint.get("canonical_resource"):
        if not isinstance(value, str):
            return False
        try:
            canonical = canonicalize_resource(value)
        except CanonicalizationError:
            return False
        if canonical != value:
            return False
    if "canonical_prefix" in constraint:
        if not isinstance(value, str):
            return False
        try:
            canonical = canonicalize_resource(value)
        except CanonicalizationError:
            return False
        if canonical != value or not canonical.startswith(str(constraint["canonical_prefix"])):
            return False
    return True


def _action_key(request: ActionRequest) -> str:
    return f"{request.tool}:{request.action}"


def _rule_matches(rule: PolicyRule, request: ActionRequest, state: RuntimeState, now: int) -> bool:
    if not fnmatch.fnmatchcase(request.subject, rule.subject):
        return False
    if not fnmatch.fnmatchcase(request.session_id, rule.session):
        return False
    if not fnmatch.fnmatchcase(request.tool, rule.tool):
        return False
    if not fnmatch.fnmatchcase(request.action, rule.action):
        return False
    if not fnmatch.fnmatchcase(request.resource or "", rule.resource):
        return False
    if rule.purpose and request.purpose not in rule.purpose:
        return False
    if rule.not_before is not None and now < rule.not_before:
        return False
    if rule.expires_at is not None and now >= rule.expires_at:
        return False

    for key, constraint in rule.param_constraints.items():
        if key not in request.params:
            if isinstance(constraint, dict) and constraint.get("required"):
                return False
            continue
        if not _matches_constraint(request.params[key], constraint):
            return False

    for key, constraint in rule.state_constraints.items():
        if key not in state.values:
            return False
        if not _matches_constraint(state.values[key], constraint):
            return False
    return True


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        if policy.default not in {"allow", "deny"}:
            raise PolicyError("policy default must be allow or deny")
        if any(rule.effect not in {"allow", "deny", "escalate"} for rule in policy.rules):
            raise PolicyError("rule effect must be allow, deny, or escalate")
        ids = [rule.rule_id for rule in policy.rules]
        if len(ids) != len(set(ids)):
            raise PolicyError("policy rule ids must be unique")
        self.policy = policy

    @property
    def version(self) -> str:
        return self.policy.version

    def evaluate(
        self,
        request: ActionRequest,
        state: RuntimeState,
        *,
        now: int = 0,
        runtime: PolicyRuntimeState | None = None,
    ) -> tuple[bool, str, str | None]:
        runtime = runtime or PolicyRuntimeState()
        emergency = self.policy.emergency_stop
        if emergency is not None and state.values.get(emergency.state_key) == emergency.equals:
            if _action_key(request) not in emergency.allow_actions:
                return False, "denied by emergency-stop policy", "emergency-stop"

        # Explicit deny and escalation rules take precedence over allow rules.
        for rule in self.policy.rules:
            if rule.effect not in {"deny", "escalate"} or not _rule_matches(rule, request, state, now):
                continue
            if rule.effect == "escalate":
                return False, f"escalation required by policy rule {rule.rule_id}", rule.rule_id
            return False, f"denied by policy rule {rule.rule_id}", rule.rule_id

        for rule in self.policy.rules:
            if rule.effect != "allow" or not _rule_matches(rule, request, state, now):
                continue
            if rule.rate_limit is not None:
                cutoff = now - rule.rate_limit.window_seconds
                recent = [ts for ts in runtime.rule_hits.get(rule.rule_id, []) if ts > cutoff]
                if len(recent) >= rule.rate_limit.max_calls:
                    return False, f"rate limit reached for policy rule {rule.rule_id}", rule.rule_id
            if runtime.authorization_history:
                _, previous_key, previous_subject, _ = runtime.authorization_history[-1]
                if previous_key in rule.forbidden_after:
                    return False, f"forbidden action sequence for policy rule {rule.rule_id}", rule.rule_id
                if previous_key in rule.separation_of_duty_after and previous_subject == request.subject:
                    return False, f"separation of duty required by policy rule {rule.rule_id}", rule.rule_id
            if rule.resource_budget is not None:
                raw_cost = request.params.get(rule.resource_budget.cost_param)
                if not isinstance(raw_cost, (int, float)) or isinstance(raw_cost, bool) or raw_cost < 0:
                    return False, f"invalid resource budget cost for policy rule {rule.rule_id}", rule.rule_id
                current = runtime.resource_usage.get(rule.resource_budget.key, 0.0)
                if current + float(raw_cost) > rule.resource_budget.max_total:
                    return False, f"resource budget exceeded for policy rule {rule.rule_id}", rule.rule_id
            return True, f"allowed by policy rule {rule.rule_id}", rule.rule_id

        allowed = self.policy.default == "allow"
        return allowed, f"policy default {self.policy.default}", None

    def record_authorization(
        self,
        rule_id: str | None,
        request: ActionRequest,
        *,
        now: int,
        runtime: PolicyRuntimeState,
    ) -> None:
        if rule_id is None:
            runtime.authorization_history.append((now, _action_key(request), request.subject, "default"))
            return
        rule = next((candidate for candidate in self.policy.rules if candidate.rule_id == rule_id), None)
        if rule is None or rule.effect != "allow":
            return
        runtime.rule_hits.setdefault(rule_id, []).append(now)
        runtime.authorization_history.append((now, _action_key(request), request.subject, rule_id))
        if rule.resource_budget is not None:
            raw_cost = request.params.get(rule.resource_budget.cost_param, 0)
            runtime.resource_usage[rule.resource_budget.key] = runtime.resource_usage.get(rule.resource_budget.key, 0.0) + float(raw_cost)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        try:
            data = load_yaml_unique(Path(path).read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid or ambiguous policy YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyError("policy document must be a mapping")
        unknown_top = set(data) - _ALLOWED_TOP_LEVEL
        if unknown_top:
            raise PolicyError(f"unknown policy fields: {sorted(unknown_top)}")

        version = data.get("version")
        default = data.get("default", "deny")
        raw_rules = data.get("rules", [])
        if not isinstance(version, str) or not version or not isinstance(raw_rules, list):
            raise PolicyError("policy requires a string version and rules list")
        if not isinstance(default, str):
            raise PolicyError("policy default must be a string")

        emergency: EmergencyStop | None = None
        raw_emergency = data.get("emergency_stop")
        if raw_emergency is not None:
            if not isinstance(raw_emergency, dict) or set(raw_emergency) - {"state_key", "equals", "allow_actions"}:
                raise PolicyError("invalid emergency_stop definition")
            state_key = raw_emergency.get("state_key")
            if not isinstance(state_key, str) or not state_key:
                raise PolicyError("emergency_stop requires state_key")
            allow_actions = raw_emergency.get("allow_actions", [])
            if not isinstance(allow_actions, list) or not all(isinstance(item, str) for item in allow_actions):
                raise PolicyError("emergency_stop allow_actions must be a list of action keys")
            emergency = EmergencyStop(state_key=state_key, equals=raw_emergency.get("equals"), allow_actions=tuple(allow_actions))

        rules: list[PolicyRule] = []
        for raw in raw_rules:
            if not isinstance(raw, dict) or "id" not in raw or "effect" not in raw:
                raise PolicyError("each rule requires id and effect")
            if not isinstance(raw["id"], str) or not raw["id"]:
                raise PolicyError("rule id must be a non-empty string")
            if not isinstance(raw["effect"], str):
                raise PolicyError(f"rule effect must be a string in rule {raw['id']}")
            unknown = set(raw) - _ALLOWED_RULE_KEYS
            if unknown:
                raise PolicyError(f"unknown fields in rule {raw.get('id')}: {sorted(unknown)}")
            for scope_key in ("subject", "session", "tool", "action", "resource"):
                if scope_key in raw and not isinstance(raw[scope_key], str):
                    raise PolicyError(f"{scope_key} must be a string in rule {raw['id']}")
            raw_params = raw.get("params", {})
            raw_state = raw.get("state", {})
            if not isinstance(raw_params, dict) or not isinstance(raw_state, dict):
                raise PolicyError(f"params and state must be mappings in rule {raw['id']}")
            params = dict(raw_params)
            state = dict(raw_state)
            for name, constraint in {**params, **state}.items():
                if not isinstance(name, str) or not name:
                    raise PolicyError(f"constraint names must be non-empty strings in rule {raw['id']}")
                _validate_constraint(name, constraint)

            raw_purpose = raw.get("purpose", ())
            if isinstance(raw_purpose, str) or not isinstance(raw_purpose, (list, tuple)):
                raise PolicyError(f"purpose must be a sequence in rule {raw['id']}")
            if not all(isinstance(item, str) and item for item in raw_purpose):
                raise PolicyError(f"purpose values must be non-empty strings in rule {raw['id']}")

            rate_limit = None
            if "rate_limit" in raw:
                value = raw["rate_limit"]
                if not isinstance(value, dict) or set(value) != {"max_calls", "window_seconds"}:
                    raise PolicyError(f"invalid rate_limit in rule {raw['id']}")
                max_calls = value["max_calls"]
                window_seconds = value["window_seconds"]
                if (
                    not isinstance(max_calls, int)
                    or isinstance(max_calls, bool)
                    or max_calls <= 0
                    or not isinstance(window_seconds, int)
                    or isinstance(window_seconds, bool)
                    or window_seconds <= 0
                ):
                    raise PolicyError(f"invalid rate_limit values in rule {raw['id']}")
                rate_limit = RateLimit(max_calls=max_calls, window_seconds=window_seconds)

            budget = None
            if "resource_budget" in raw:
                value = raw["resource_budget"]
                if not isinstance(value, dict) or set(value) != {"key", "cost_param", "max_total"}:
                    raise PolicyError(f"invalid resource_budget in rule {raw['id']}")
                if not isinstance(value["key"], str) or not isinstance(value["cost_param"], str):
                    raise PolicyError(f"invalid resource_budget identifiers in rule {raw['id']}")
                if (
                    not isinstance(value["max_total"], (int, float))
                    or isinstance(value["max_total"], bool)
                    or value["max_total"] < 0
                ):
                    raise PolicyError(f"invalid resource_budget limit in rule {raw['id']}")
                budget = ResourceBudget(value["key"], value["cost_param"], float(value["max_total"]))

            raw_forbidden = raw.get("forbidden_after", ())
            raw_separation = raw.get("separation_of_duty_after", ())
            if (
                isinstance(raw_forbidden, str)
                or not isinstance(raw_forbidden, (list, tuple))
                or isinstance(raw_separation, str)
                or not isinstance(raw_separation, (list, tuple))
            ):
                raise PolicyError(f"sequence constraints must be sequences in rule {raw['id']}")
            forbidden_after = tuple(raw_forbidden)
            separation = tuple(raw_separation)
            if not all(isinstance(item, str) and item for item in (*forbidden_after, *separation)):
                raise PolicyError(f"sequence constraints must contain action keys in rule {raw['id']}")

            not_before = raw.get("not_before")
            expires_at = raw.get("expires_at")
            for field_name, value in (("not_before", not_before), ("expires_at", expires_at)):
                if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                    raise PolicyError(f"{field_name} must be an integer in rule {raw['id']}")
            if not_before is not None and expires_at is not None and expires_at <= not_before:
                raise PolicyError(f"invalid temporal interval in rule {raw['id']}")

            rules.append(
                PolicyRule(
                    rule_id=str(raw["id"]),
                    effect=str(raw["effect"]),
                    subject=str(raw.get("subject", "*")),
                    session=str(raw.get("session", "*")),
                    tool=str(raw.get("tool", "*")),
                    action=str(raw.get("action", "*")),
                    resource=str(raw.get("resource", "*")),
                    param_constraints=params,
                    state_constraints=state,
                    purpose=tuple(raw_purpose),
                    not_before=not_before,
                    expires_at=expires_at,
                    rate_limit=rate_limit,
                    forbidden_after=forbidden_after,
                    separation_of_duty_after=separation,
                    resource_budget=budget,
                )
            )
        return cls(Policy(version=version, default=default, rules=tuple(rules), emergency_stop=emergency))
