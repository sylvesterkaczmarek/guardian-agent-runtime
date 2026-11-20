import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from guardian_runtime.adapters import AdapterSpec, EffectObserver
from guardian_runtime.adversarial import benign_scenarios
from guardian_runtime.crypto import load_public_key_b64
from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.factory import build_guardian
from guardian_runtime.simulator import SandboxEnvironment
from guardian_runtime.study.pilot import execute_guardian, run_pilot
from guardian_runtime.study.reference_controls import reference_outcomes
from guardian_runtime.study.scoring import verify_claims
from guardian_runtime.study.workflows import FAMILIES, StudyEnvironment, proposal


def test_true_v041_bundle_verifies():
    fixture = json.loads((Path(__file__).parents[1] / "fixtures/evidence-0.4.1.json").read_text())
    bundle = fixture["bundle"]
    key = load_public_key_b64(fixture["public_key"])
    assert verify_evidence_bundle(bundle, key)[0]
    assert not verify_evidence_bundle({**bundle, "format": "guardian-evidence-bundle-v2"}, key)[0]


def test_reference_scores_capture_real_state_after_tool_error():
    rows = reference_outcomes()
    assert len(rows) == 13 and all(r["verified"] for r in rows)
    assert all(r["completed"] for r in rows[:11])
    assert (rows[-2]["tool_acknowledgements"], rows[-2]["observed_effects"]) == ([True], [False])
    assert (rows[-1]["tool_acknowledgements"], rows[-1]["observed_effects"]) == ([False], [True])


def test_adapter_and_permit_lifetime_are_bound_to_manifest():
    class Other(SandboxEnvironment):
        pass
    r, m, _ = build_guardian("sandbox", hardened=True)
    _, other, _ = build_guardian("sandbox", hardened=True, environment_override=Other())
    _, longer, _ = build_guardian("sandbox", hardened=True, permit_ttl_seconds=60)
    assert len({m.manifest_hash, other.manifest_hash, longer.manifest_hash}) == 3
    r.execute_request(benign_scenarios()[5].requests[0])
    bundle = r.evidence.export_bundle(policy_version=r.policy.version)
    assert not verify_evidence_bundle(bundle, r.public_key, expected_manifest_hash=longer.manifest_hash)[0]


@pytest.mark.parametrize("family", FAMILIES)
def test_composed_children_and_observations_are_bound_to_the_right_parent(family):
    req = proposal(family)
    env, decision, result, bundle, manifest, key, _ = execute_guardian(family, "excursion", "trajectory", req)
    assert decision.allowed and result.ok
    prepare, apply, outer = bundle["events"]
    assert prepare["parent_permit_id"] == apply["parent_permit_id"] == outer["permit_id"]
    assert len({record["permit_id"] for record in (prepare, apply, outer)}) == 3
    assert [r["normalized_action"]["action"] for r in bundle["events"]] == ["prepare", "apply", req.action]
    expected = {"completion": True, "endpoint_in_range": True, "trajectory_in_range": False}
    assert verify_claims(bundle, key, manifest.manifest_hash, req, family+"-trajectory", env.commits[-1]) == expected
    assert all(x is None for x in verify_claims(bundle, key, manifest.manifest_hash, replace(req, nonce="other"),
                                                 family+"-trajectory", env.commits[-1]).values())
    apply["observation"]["readings"]["samples"] = [0, env.commits[-1]]
    assert not verify_evidence_bundle(bundle, key)[0]


def test_denied_child_is_linked_and_later_children_do_not_run():
    env = StudyEnvironment("joint", "normal")
    make_children = env.build_nested_requests
    env.build_nested_requests = lambda r: (replace(make_children(r)[0], capability_id="missing"), make_children(r)[1])
    runtime, _, _ = env.runtime()
    dec, res = runtime.execute_request(proposal("joint"))
    assert dec.allowed and not res.ok and env.invocations == 0
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    child, parent = bundle["events"]
    assert child["decision"] == "deny" and child["parent_permit_id"] == parent["permit_id"]
    assert verify_evidence_bundle(bundle, runtime.public_key)[0]


def test_observer_failure_preserves_audited_tool_result():
    env = StudyEnvironment("joint", "normal")
    def fail(request, result):
        raise OSError("sensor offline")
    env.read_observer = fail
    runtime, _, _ = env.runtime()
    _, res = runtime.execute_request(proposal("joint"))
    assert res.ok and runtime.evidence.events[-1].observation["readings"] is None
    assert verify_evidence_bundle(runtime.evidence.export_bundle(policy_version=runtime.policy.version), runtime.public_key)[0]


def test_pilot_scores_stale_and_missing_observations_as_unknown(monkeypatch):
    # A physical sensor may have moved on by the time the comparator runs.
    read = StudyEnvironment.read_observer
    seen = set()

    def read_once(env, request, result):
        if request.action == "apply":
            if env in seen:
                pytest.fail("pilot sampled the same operation twice")
            seen.add(env)
        return read(env, request, result)

    monkeypatch.setattr(StudyEnvironment, "read_observer", read_once)
    report, samples = run_pilot()
    assert len(seen) == 42
    assert len(report["rows"]) == 42
    for family in FAMILIES:
        rows = [r for r in report["rows"] if r["family"] == family]
        assert all(r["truth_agrees_across_executions"] for r in rows)
        assert all(all(v is None for v in r["verdicts"]["guardian"].values()) for r in rows if r["mode"] in {"missing", "delayed"})
        assert all(r["verdicts"]["simple_checker"] == r["verdicts"]["guardian"] for r in rows)
        counts = report["summary"][family]["by_method"]["guardian"]
        assert counts["false_confirmations"] == 0 and counts["correctly_resolved_answerable"] == counts["predicted_answerable"] == 26
        assert asdict(proposal(family))["action"] == FAMILIES[family][0]
        assert len(samples[family]["bundle"]["events"]) == 3
    assert all(not r["guardian_admitted"] and not r["gateway_admitted"] and r["guardian_invocations"] == r["gateway_invocations"] == 0 for r in report["prevention_controls"])


def test_adapter_contract_validation():
    with pytest.raises(ValueError):
        AdapterSpec("worker", "bad")
    with pytest.raises(ValueError):
        AdapterSpec("worker", "0"*64, ("dup", "dup"))
    with pytest.raises(ValueError):
        EffectObserver("", lambda r, s: {})


def test_partial_observations_can_refute_but_cannot_confirm_a_trajectory():
    from guardian_runtime.study.scoring import assess

    incomplete = {"samples": [0, 7], "terminal": False, "complete": False}
    assert assess(incomplete, 3) == {"completion": None, "endpoint_in_range": None, "trajectory_in_range": False}
    assert assess({**incomplete, "samples": [0, 2]}, 3)["trajectory_in_range"] is None
    assert assess({"samples": [3], "terminal": True, "complete": False}, 3) == {
        "completion": True, "endpoint_in_range": True, "trajectory_in_range": None,
    }


@pytest.mark.parametrize("readings", [
    {"samples": [True], "terminal": True, "complete": True},
    {"samples": [3], "terminal": "yes", "complete": True},
    {"samples": [3], "terminal": False, "complete": True},
])
def test_simple_checker_leaves_invalid_or_unfinished_observations_unknown(readings):
    from guardian_runtime.study.scoring import simple_checker
    assert all(v is None for v in simple_checker(readings, 3).values())


def test_fresh_policy_is_required_for_each_child():
    env = StudyEnvironment("joint", "normal")
    original = env.execute

    def execute(request):
        result = original(request)
        if request.action == "prepare":
            env.ready = False
        return result

    env.execute = execute
    runtime, _, _ = env.runtime()
    decision, result = runtime.execute_request(proposal("joint"))
    assert decision.allowed and not result.ok and env.invocations == 0
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    assert [e["decision"] for e in bundle["events"]] == ["allow", "deny", "allow"]
    assert verify_evidence_bundle(bundle, runtime.public_key)[0]
