import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from guardian_runtime.capabilities import Capability, capability_is_subset
from guardian_runtime.factory import build_guardian
from guardian_runtime.types import ActionRequest


@settings(max_examples=100, deadline=None)
@given(st.floats(min_value=3.000001, max_value=1000, allow_nan=False, allow_infinity=False), st.booleans())
def test_out_of_capability_maneuvers_never_execute(magnitude, negative):
    value = -magnitude if negative else magnitude
    runtime, _, _ = build_guardian("mission", hardened=True)
    request = ActionRequest(
        subject="agent-1",
        session_id="property",
        tool="mission",
        action="maneuver",
        params={"delta_v": value},
        purpose="operations",
        capability_id="cap-maneuver",
        nonce="property-nonce",
    )
    decision, result = runtime.execute_request(request)
    assert not decision.allowed
    assert result is None
    assert runtime.environment.state.cumulative_delta_v == 0


@settings(max_examples=75, deadline=None)
@given(st.lists(st.floats(min_value=-3, max_value=3, allow_nan=False, allow_infinity=False), min_size=1, max_size=10))
def test_authorized_maneuver_sequences_remain_within_accumulated_bound(values):
    runtime, _, _ = build_guardian("mission", hardened=True)
    for index, value in enumerate(values):
        request = ActionRequest(
            subject="agent-1",
            session_id="property-sequence",
            tool="mission",
            action="maneuver",
            params={"delta_v": value},
            purpose="operations",
            capability_id="cap-maneuver",
            nonce=f"n-{index}",
        )
        decision, result = runtime.execute_request(request)
        assert decision.allowed and result and result.ok
    assert abs(runtime.environment.state.cumulative_delta_v) <= 30.0


@settings(max_examples=100, deadline=None)
@given(
    parent_min=st.integers(min_value=-100, max_value=0),
    parent_max=st.integers(min_value=1, max_value=100),
    tighten_low=st.integers(min_value=0, max_value=20),
    tighten_high=st.integers(min_value=0, max_value=20),
)
def test_narrower_numeric_delegation_is_subset(parent_min, parent_max, tighten_low, tighten_high):
    child_min = min(parent_max, parent_min + tighten_low)
    child_max = max(child_min, parent_max - tighten_high)
    parent = Capability(
        "p",
        "agent-1",
        "sandbox",
        "actuator_set",
        "*",
        constraints={"value": {"min": parent_min, "max": parent_max, "required": True}},
        purpose=("operations",),
        max_invocations=10,
        delegation_depth=2,
        expires_at=100,
    )
    child = Capability(
        "c",
        "agent-1",
        "sandbox",
        "actuator_set",
        "*",
        constraints={"value": {"min": child_min, "max": child_max, "required": True}},
        purpose=("operations",),
        max_invocations=5,
        delegation_depth=1,
        parent_id="p",
        expires_at=90,
    )
    assert capability_is_subset(child, parent)


@settings(max_examples=80, deadline=None)
@given(st.text(min_size=1).filter(lambda value: value != value.strip()))
def test_ambiguous_identifier_whitespace_fails_closed(action):
    runtime, _, _ = build_guardian("mission", hardened=True)
    request = ActionRequest(
        subject="agent-1",
        session_id="property",
        tool="mission",
        action=action,
        params={},
        purpose="operations",
        capability_id="cap-observe",
        nonce="whitespace",
    )
    decision, result = runtime.execute_request(request)
    assert not decision.allowed
    assert result is None


@settings(max_examples=75, deadline=None)
@given(st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=24))
def test_capability_nonce_is_single_use(nonce):
    runtime, _, _ = build_guardian("mission", hardened=True)
    request = ActionRequest(
        subject="agent-1",
        session_id="property-nonce",
        tool="mission",
        action="observe_telemetry",
        purpose="operations",
        capability_id="cap-observe",
        nonce=nonce,
    )
    first, first_result = runtime.execute_request(request)
    second, second_result = runtime.execute_request(request)
    assert first.allowed and first_result and first_result.ok
    assert not second.allowed
    assert second_result is None


@settings(max_examples=100, deadline=None)
@given(
    lower=st.integers(min_value=-100, max_value=-1),
    upper=st.integers(min_value=1, max_value=100),
    widening=st.integers(min_value=1, max_value=50),
)
def test_delegation_that_widens_numeric_authority_is_rejected(lower, upper, widening):
    parent = Capability(
        "p-wide-check",
        "agent-1",
        "sandbox",
        "actuator_set",
        "*",
        constraints={"value": {"min": lower, "max": upper, "required": True}},
        purpose=("operations",),
        max_invocations=10,
        delegation_depth=2,
        expires_at=100,
    )
    child = Capability(
        "c-wide-check",
        "agent-1",
        "sandbox",
        "actuator_set",
        "*",
        constraints={
            "value": {
                "min": lower - widening,
                "max": upper + widening,
                "required": True,
            }
        },
        purpose=("operations",),
        max_invocations=5,
        delegation_depth=1,
        parent_id="p-wide-check",
        expires_at=90,
    )
    assert not capability_is_subset(child, parent)
