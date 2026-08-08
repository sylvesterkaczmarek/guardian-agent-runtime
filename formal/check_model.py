from __future__ import annotations

from collections import deque
from dataclasses import dataclass


MAX_DEPTH = 8
MAX_TIME = 3
MAX_STATE_VERSION = 1
MAX_PERMITS = 2
PERMIT_TTL = 2


@dataclass(frozen=True)
class RequestSpec:
    required_authority: int
    policy_allowed: bool
    invariant_safe: bool


@dataclass(frozen=True)
class CapabilitySpec:
    authority: int
    expires_at: int
    parent: str | None = None


REQUESTS = {
    "observe": RequestSpec(required_authority=1, policy_allowed=True, invariant_safe=True),
    "restricted": RequestSpec(required_authority=2, policy_allowed=False, invariant_safe=True),
    "unsafe": RequestSpec(required_authority=1, policy_allowed=True, invariant_safe=False),
}

CAPABILITIES = {
    "parent": CapabilitySpec(authority=1, expires_at=3),
    "child": CapabilitySpec(authority=1, expires_at=3, parent="parent"),
    # This capability is a deliberately invalid delegation candidate. The transition
    # system must never make it available because it exceeds its parent's authority.
    "escalated_child": CapabilitySpec(authority=2, expires_at=3, parent="parent"),
}


@dataclass(frozen=True)
class Permit:
    permit_id: int
    request: str
    capability: str
    issued_at: int
    expires_at: int
    state_version: int


@dataclass(frozen=True)
class ExecutionRecord:
    permit_id: int
    request: str
    capability: str
    authorized_at_execution: bool
    policy_allowed_at_execution: bool
    invariant_safe_at_execution: bool
    lineage_active_at_execution: bool
    state_bound_at_execution: bool
    unexpired_at_execution: bool


@dataclass(frozen=True)
class State:
    now: int = 0
    state_version: int = 0
    delegated: frozenset[str] = frozenset()
    revoked: frozenset[str] = frozenset()
    permits: tuple[Permit, ...] = ()
    used_permits: frozenset[int] = frozenset()
    executed: tuple[ExecutionRecord, ...] = ()
    evidence: tuple[int, ...] = ()
    next_permit_id: int = 1


def _available(capability: str, state: State) -> bool:
    spec = CAPABILITIES[capability]
    return spec.parent is None or capability in state.delegated


def _lineage(capability: str) -> tuple[str, ...]:
    out = [capability]
    seen = {capability}
    current = capability
    while CAPABILITIES[current].parent is not None:
        parent = CAPABILITIES[current].parent
        assert parent is not None
        if parent in seen:
            raise AssertionError("delegation cycle in bounded model")
        out.append(parent)
        seen.add(parent)
        current = parent
    return tuple(out)


def _lineage_active(capability: str, state: State) -> bool:
    if not _available(capability, state):
        return False
    for item in _lineage(capability):
        spec = CAPABILITIES[item]
        if item in state.revoked or state.now >= spec.expires_at:
            return False
    return True


def _delegation_is_subset(child: str, parent: str) -> bool:
    child_spec = CAPABILITIES[child]
    parent_spec = CAPABILITIES[parent]
    return child_spec.parent == parent and child_spec.authority <= parent_spec.authority and child_spec.expires_at <= parent_spec.expires_at


def _capability_authorizes(request: str, capability: str, state: State) -> bool:
    req = REQUESTS[request]
    cap = CAPABILITIES[capability]
    return _lineage_active(capability, state) and req.required_authority <= cap.authority


def _can_authorize(request: str, capability: str, state: State) -> bool:
    req = REQUESTS[request]
    return (
        state.next_permit_id <= MAX_PERMITS
        and _capability_authorizes(request, capability, state)
        and req.policy_allowed
        and req.invariant_safe
    )


def _can_execute(permit: Permit, state: State) -> bool:
    req = REQUESTS[permit.request]
    return (
        permit.permit_id not in state.used_permits
        and state.now < permit.expires_at
        and _lineage_active(permit.capability, state)
        and state.state_version == permit.state_version
        and req.policy_allowed
        and req.invariant_safe
        and req.required_authority <= CAPABILITIES[permit.capability].authority
    )


def successors(state: State):
    # Delegation is allowed only when it narrows or preserves authority. The invalid
    # escalated child is intentionally present in CAPABILITIES but has no valid transition.
    for child in ("child", "escalated_child"):
        parent = CAPABILITIES[child].parent
        assert parent is not None
        if (
            child not in state.delegated
            and _available(parent, state)
            and _lineage_active(parent, state)
            and _delegation_is_subset(child, parent)
        ):
            yield State(
                now=state.now,
                state_version=state.state_version,
                delegated=state.delegated | {child},
                revoked=state.revoked,
                permits=state.permits,
                used_permits=state.used_permits,
                executed=state.executed,
                evidence=state.evidence,
                next_permit_id=state.next_permit_id,
            )

    # Authorization binds capability, policy decision, safety state, time, and current
    # runtime-state version into a short-lived permit.
    for request in REQUESTS:
        for capability in CAPABILITIES:
            if not _can_authorize(request, capability, state):
                continue
            permit = Permit(
                permit_id=state.next_permit_id,
                request=request,
                capability=capability,
                issued_at=state.now,
                expires_at=min(state.now + PERMIT_TTL, CAPABILITIES[capability].expires_at),
                state_version=state.state_version,
            )
            yield State(
                now=state.now,
                state_version=state.state_version,
                delegated=state.delegated,
                revoked=state.revoked,
                permits=state.permits + (permit,),
                used_permits=state.used_permits,
                executed=state.executed,
                evidence=state.evidence,
                next_permit_id=state.next_permit_id + 1,
            )

    # Revocation is monotonic. Revoking a parent makes descendants inactive through
    # _lineage_active even if the child itself was never explicitly revoked.
    for capability in CAPABILITIES:
        if _available(capability, state) and capability not in state.revoked:
            yield State(
                now=state.now,
                state_version=state.state_version,
                delegated=state.delegated,
                revoked=state.revoked | {capability},
                permits=state.permits,
                used_permits=state.used_permits,
                executed=state.executed,
                evidence=state.evidence,
                next_permit_id=state.next_permit_id,
            )

    # Time and state changes challenge expiry and TOCTOU binding.
    if state.now < MAX_TIME:
        yield State(
            now=state.now + 1,
            state_version=state.state_version,
            delegated=state.delegated,
            revoked=state.revoked,
            permits=state.permits,
            used_permits=state.used_permits,
            executed=state.executed,
            evidence=state.evidence,
            next_permit_id=state.next_permit_id,
        )
    if state.state_version < MAX_STATE_VERSION:
        yield State(
            now=state.now,
            state_version=state.state_version + 1,
            delegated=state.delegated,
            revoked=state.revoked,
            permits=state.permits,
            used_permits=state.used_permits,
            executed=state.executed,
            evidence=state.evidence,
            next_permit_id=state.next_permit_id,
        )

    # Execution is possible only through an unused, unexpired, state-bound permit whose
    # full capability lineage remains active and whose request still satisfies policy and
    # safety predicates. Every execution appends one evidence identifier atomically.
    for permit in state.permits:
        if not _can_execute(permit, state):
            continue
        req = REQUESTS[permit.request]
        record = ExecutionRecord(
            permit_id=permit.permit_id,
            request=permit.request,
            capability=permit.capability,
            authorized_at_execution=req.required_authority <= CAPABILITIES[permit.capability].authority,
            policy_allowed_at_execution=req.policy_allowed,
            invariant_safe_at_execution=req.invariant_safe,
            lineage_active_at_execution=_lineage_active(permit.capability, state),
            state_bound_at_execution=state.state_version == permit.state_version,
            unexpired_at_execution=state.now < permit.expires_at,
        )
        yield State(
            now=state.now,
            state_version=state.state_version,
            delegated=state.delegated,
            revoked=state.revoked,
            permits=state.permits,
            used_permits=state.used_permits | {permit.permit_id},
            executed=state.executed + (record,),
            evidence=state.evidence + (permit.permit_id,),
            next_permit_id=state.next_permit_id,
        )


def assert_invariants(state: State) -> None:
    # P1/P2/P10: execution authority is valid and delegation cannot increase it.
    assert all(record.authorized_at_execution for record in state.executed)
    assert all(_delegation_is_subset(child, CAPABILITIES[child].parent or "") for child in state.delegated)
    assert "escalated_child" not in state.delegated

    # P3: revoked/expired capability lineages and expired permits cannot execute.
    assert all(record.lineage_active_at_execution for record in state.executed)
    assert all(record.unexpired_at_execution for record in state.executed)

    # P4/P7: every execution has one evidence record and evidence does not silently lose
    # or duplicate a permit identifier in the bounded transition system.
    assert len(state.evidence) == len(state.executed)
    assert state.evidence == tuple(record.permit_id for record in state.executed)

    # P5/P8/P9: policy-denied, unsafe, or stale-state requests do not execute.
    assert all(record.policy_allowed_at_execution for record in state.executed)
    assert all(record.invariant_safe_at_execution for record in state.executed)
    assert all(record.state_bound_at_execution for record in state.executed)

    # Permit replay protection is exact in the bounded model.
    assert len(state.used_permits) == len(state.executed)
    assert state.used_permits == frozenset(record.permit_id for record in state.executed)
    assert len({record.permit_id for record in state.executed}) == len(state.executed)


def check_model(max_depth: int = MAX_DEPTH) -> int:
    initial = State()
    queue = deque([(initial, 0)])
    seen = {initial}
    while queue:
        state, depth = queue.popleft()
        assert_invariants(state)
        if depth >= max_depth:
            continue
        for successor in successors(state):
            assert_invariants(successor)
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, depth + 1))
    return len(seen)


if __name__ == "__main__":
    count = check_model()
    print(
        "bounded Guardian state model: "
        f"{count} reachable states checked across capability, delegation, policy, "
        "revocation, expiry, TOCTOU, permit replay, and evidence transitions"
    )
