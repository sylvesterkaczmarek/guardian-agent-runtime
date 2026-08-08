from dataclasses import asdict

from guardian_runtime.evidence import verify_evidence_bundle, verify_events
from guardian_runtime.factory import build_guardian
from guardian_runtime.types import ActionRequest


def _request(nonce):
    return ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="mission",
        action="observe_telemetry",
        params={},
        purpose="operations",
        capability_id="cap-observe",
        nonce=nonce,
    )


def test_modified_event_fails_verification():
    runtime, signed_manifest, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    events = [asdict(event) for event in runtime.evidence.events]
    events[0]["decision_reason"] = "tampered"
    ok, _ = verify_events(events, runtime.public_key, expected_manifest_hash=signed_manifest.manifest_hash)
    assert not ok


def test_reordered_events_fail_verification():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    runtime.execute_request(_request("n2"))
    events = [asdict(event) for event in runtime.evidence.events]
    ok, _ = verify_events(list(reversed(events)), runtime.public_key)
    assert not ok


def test_signed_checkpoint_detects_tail_deletion():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    runtime.execute_request(_request("n2"))
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    ok, _ = verify_evidence_bundle(bundle, runtime.public_key)
    assert ok

    bundle["events"] = bundle["events"][:-1]
    ok, reason = verify_evidence_bundle(bundle, runtime.public_key)
    assert not ok
    assert "count" in reason or "terminal" in reason


def test_raw_shorter_chain_is_internally_valid_but_not_deletion_complete():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    runtime.execute_request(_request("n2"))
    raw = [asdict(event) for event in runtime.evidence.events]
    ok, _ = verify_events(raw[:-1], runtime.public_key)
    assert ok
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    bundle["events"] = bundle["events"][:-1]
    assert not verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_replayed_event_is_rejected():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    runtime.execute_request(_request("n2"))
    raw = [asdict(event) for event in runtime.evidence.events]
    replayed = [raw[0], raw[0], raw[1]]
    ok, _ = verify_events(replayed, runtime.public_key)
    assert not ok


def test_signature_failure_is_rejected():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    raw = [asdict(event) for event in runtime.evidence.events]
    raw[0]["signature"] = "AAAA"
    ok, reason = verify_events(raw, runtime.public_key)
    assert not ok
    assert "signature" in reason


def test_policy_version_mismatch_is_rejected():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    ok, reason = verify_evidence_bundle(
        bundle, runtime.public_key, expected_policy_version="different-policy"
    )
    assert not ok
    assert "policy version mismatch" in reason


def test_broken_hash_chain_is_rejected():
    runtime, _, _ = build_guardian("mission", hardened=True)
    runtime.execute_request(_request("n1"))
    runtime.execute_request(_request("n2"))
    raw = [asdict(event) for event in runtime.evidence.events]
    raw[1]["previous_hash"] = "f" * 64
    ok, reason = verify_events(raw, runtime.public_key)
    assert not ok
    assert "broken hash chain" in reason
