from copy import deepcopy
from dataclasses import replace

import pytest

from guardian_runtime.canonical import digest_json
from guardian_runtime.crypto import sign_object, verify_object
from guardian_runtime.evidence import verify_evidence_bundle, verify_events
from guardian_runtime.evidence.log import _safe_value
from guardian_runtime.factory import build_guardian
from guardian_runtime.types import ActionRequest, ToolResult


def _request(**changes):
    request = ActionRequest(
        subject="agent-1", session_id="s", tool="mission", action="observe_telemetry",
        purpose="operations", capability_id="cap-observe", nonce="evidence-boundary",
    )
    return replace(request, **changes)


@pytest.fixture
def signed_bundle():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request())
    return runtime, runtime.evidence.export_bundle(policy_version=runtime.policy.version)


@pytest.mark.parametrize("field,value", [
    ("event_hash", []), ("event_hash", {}), ("previous_hash", []),
    ("sequence", True), ("sequence", 1.0), ("timestamp", True),
    ("subject", []), ("session_id", 1), ("requested_action", []),
    ("normalized_action", []), ("decision", []), ("decision", "approved"),
    ("decision_reason", {}), ("rule_id", 1), ("policy_version", []),
    ("capability_id", None), ("runtime_manifest_hash", []),
    ("result_digest", []), ("signature", []),
])
def test_malformed_event_fields_fail_closed(signed_bundle, field, value):
    runtime, bundle = signed_bundle
    bundle["events"][0][field] = value
    ok, reason = verify_evidence_bundle(bundle, runtime.public_key)
    assert not ok
    assert "malformed evidence event" in reason


@pytest.mark.parametrize("field,value", [
    ("event_count", True), ("event_count", 1.0), ("event_count", -1),
    ("terminal_hash", []), ("runtime_manifest_hash", {}),
    ("policy_version", []), ("signature", []),
])
def test_malformed_checkpoint_fields_fail_closed(signed_bundle, field, value):
    runtime, bundle = signed_bundle
    bundle["checkpoint"][field] = value
    assert not verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_signed_boolean_count_is_not_an_event_count(signed_bundle):
    runtime, bundle = signed_bundle
    checkpoint = bundle["checkpoint"]
    checkpoint["event_count"] = True
    unsigned = {key: value for key, value in checkpoint.items() if key != "signature"}
    checkpoint["signature"] = sign_object(runtime.signing_key, unsigned)
    assert not verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_cyclic_tampered_event_is_rejected_without_crash(signed_bundle):
    runtime, bundle = signed_bundle
    bundle["events"][0]["requested_action"]["context"] = bundle
    assert not verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_cyclic_verification_payload_is_rejected(signed_bundle):
    runtime, _ = signed_bundle
    cyclic = {}
    cyclic["self"] = cyclic
    assert not verify_object(runtime.public_key, cyclic, "AAAA")


def test_empty_checkpoint_remains_valid_and_anchored():
    runtime, _, _ = build_guardian("mission", hardened=True)
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    assert verify_evidence_bundle(bundle, runtime.public_key) == (True, "evidence bundle valid")


@pytest.mark.parametrize("container", ["mapping", "list"])
def test_cyclic_request_leaves_a_signed_denial(container):
    runtime, _, _ = build_guardian("mission", hardened=True)
    cycle = {} if container == "mapping" else []
    if container == "mapping":
        cycle["self"] = cycle
    else:
        cycle.append(cycle)
    decision, result = runtime.execute_request(_request(params={"cyclic": cycle}))
    assert not decision.allowed and result is None
    assert runtime.gateway.execution_count == 0
    assert len(runtime.evidence.events) == 1
    assert "invalid_cycle" in str(runtime.evidence.events[0].requested_action)
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    assert verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_cyclic_tool_output_does_not_erase_execution_evidence(monkeypatch):
    runtime, _, _ = build_guardian("mission", hardened=True)
    cycle = {}
    cycle["self"] = cycle
    monkeypatch.setattr(runtime.environment, "execute", lambda _: ToolResult(True, "cyclic", cycle, 0))
    decision, result = runtime.execute_request(_request())
    assert decision.allowed and result.ok
    assert runtime.gateway.execution_count == 1
    assert len(runtime.evidence.events) == 1
    assert runtime.evidence.events[0].result_digest == digest_json({
        "ok": True, "status": "cyclic", "output": {"self": {"invalid_cycle": "builtins.dict"}},
        "state_version": 0,
    })
    assert verify_events(runtime.evidence.events, runtime.public_key)[0]


@pytest.mark.parametrize("field,value", [
    ("params", {"bad": "\ud800"}), ("params", {"\ud800": "bad key"}),
    ("subject", "\ud800"), ("session_id", "\ud800"), ("capability_id", "\ud800"),
])
def test_invalid_unicode_request_leaves_a_signed_denial(field, value):
    runtime, _, _ = build_guardian("mission", hardened=True)
    decision, result = runtime.execute_request(_request(**{field: value}))
    assert not decision.allowed and result is None
    assert len(runtime.evidence.events) == 1
    assert verify_events(runtime.evidence.events, runtime.public_key)[0]


def test_evidence_depth_is_explicitly_truncated():
    nested = {}
    for _ in range(1000):
        nested = {"next": nested}
    snapshot = _safe_value(nested)
    assert "maximum nesting depth" in str(snapshot)
    assert digest_json(snapshot)


def test_shared_values_are_preserved_as_values_not_mistaken_for_cycles():
    shared = {"nested": [1, 2, 3]}
    value = {"a": shared, "b": shared}
    assert _safe_value(value) == deepcopy(value)


def test_wrong_bundle_type_is_rejected():
    runtime, _, _ = build_guardian("mission", hardened=True)
    assert verify_evidence_bundle([], runtime.public_key) == (False, "evidence bundle must be an object")


def test_oversized_integer_request_remains_auditable():
    runtime, _, _ = build_guardian("mission", hardened=True)
    value = 10 ** 10000
    decision, result = runtime.execute_request(_request(params={"huge": value}))
    assert not decision.allowed and result is None
    assert runtime.evidence.events[0].requested_action["params"]["huge"] == {
        "invalid_integer_hex": hex(value),
    }
    assert verify_events(runtime.evidence.events, runtime.public_key)[0]


def test_bundle_checkpoint_uses_the_same_event_snapshot(signed_bundle, monkeypatch):
    from dataclasses import asdict

    import guardian_runtime.evidence.log as evidence_module
    from guardian_runtime.types import EvidenceEvent

    runtime, _ = signed_bundle
    appended = False

    def append_after_first_exported_event(value):
        nonlocal appended
        snapshot = asdict(value)
        if isinstance(value, EvidenceEvent) and not appended:
            appended = True
            runtime.execute_request(_request(nonce="during-export"))
        return snapshot

    monkeypatch.setattr(evidence_module, "asdict", append_after_first_exported_event)
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    assert appended and len(runtime.evidence.events) == 2
    assert len(bundle["events"]) == bundle["checkpoint"]["event_count"] == 1
    assert verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_concurrent_appends_produce_one_valid_sequence():
    from concurrent.futures import ThreadPoolExecutor

    from guardian_runtime.crypto import deterministic_private_key
    from guardian_runtime.evidence import EvidenceLog
    from guardian_runtime.types import Decision

    key = deterministic_private_key("concurrent-evidence")
    log = EvidenceLog(key, "a" * 64)

    def append(index):
        log.append(
            timestamp=index, request=_request(nonce=str(index)),
            decision=Decision(False, "test denial"), policy_version="test-v1", result=None,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(100)))
    assert len(log.events) == 100
    assert verify_evidence_bundle(log.export_bundle(policy_version="test-v1"), key.public_key())[0]
