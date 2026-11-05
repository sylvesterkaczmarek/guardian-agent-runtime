"""Independent release checks using synthetic tools and ephemeral signing keys."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
import subprocess
import sys
from threading import Barrier

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian_runtime.capabilities import Capability, CapabilityStore, capability_is_subset
from guardian_runtime.crypto import public_key_b64
from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.guardian import GuardianRuntime
from guardian_runtime.manifest import sign_manifest, verify_manifest
from guardian_runtime.policy import EmergencyStop, Policy, PolicyEngine, PolicyRule, RateLimit, ResourceBudget
from guardian_runtime.simulator import SandboxEnvironment
from guardian_runtime.tools import PermitError
from guardian_runtime.types import ActionRequest, RuntimeState, ToolResult

KEY = Ed25519PrivateKey.generate()


def request(**changes):
    return replace(
        ActionRequest(
            "reviewer",
            "isolated",
            "sandbox",
            "read_file",
            resource="/tmp/input.txt",
            capability_id="root",
            nonce="once",
        ),
        **changes,
    )


def runtime(rules=(), default="allow", environment=None, emergency=None):
    clock = [100]
    monitor = GuardianRuntime(
        capabilities=CapabilityStore(
            [Capability("root", "reviewer", "sandbox", "*", constraints={"cost": {}, "value": {}, "content": {}})]
        ),
        policy=PolicyEngine(Policy("review-v1", default, tuple(rules), emergency)),
        environment=environment or SandboxEnvironment(),
        signing_key=KEY,
        runtime_manifest_hash="b" * 64,
        clock=lambda: clock[0],
        permit_ttl_seconds=10,
    )
    return monitor, clock


def valid_bundle(monitor):
    bundle = monitor.evidence.export_bundle(policy_version=monitor.policy.version)
    assert verify_evidence_bundle(
        bundle,
        monitor.public_key,
        expected_policy_version=monitor.policy.version,
        expected_manifest_hash=monitor.runtime_manifest_hash,
    )[0]
    return bundle


@pytest.mark.parametrize("fallback", ["default", "rule"])
@pytest.mark.parametrize("restriction", ["budget", "rate"])
def test_new_first_matching_allow_rule_requires_new_reservation(fallback, restriction):
    constraints = (
        {"resource_budget": ResourceBudget("restricted", "cost", 0)}
        if restriction == "budget"
        else {"rate_limit": RateLimit(1, 60)}
    )
    stricter = PolicyRule("later-restriction", "allow", not_before=101, **constraints)
    rules = [stricter] + ([PolicyRule("fallback", "allow")] if fallback == "rule" else [])
    monitor, clock = runtime(rules=rules)
    decision = monitor.evaluate(request(params={"cost": 1}))
    assert decision.allowed
    clock[0] = 101
    if restriction == "rate":
        assert monitor.evaluate(request(params={"cost": 1}, nonce="new-reservation")).allowed
    assert not monitor.evaluate(request(params={"cost": 1}, nonce="fresh-control")).allowed
    with pytest.raises(PermitError):
        monitor.gateway.execute(decision.normalized_request, decision.permit)
    assert monitor.gateway.execution_count == 0


@pytest.mark.parametrize("unrelated", ["different-action", "nonmatching-params", "later-order"])
def test_unrelated_allow_rules_do_not_invalidate_reservation(unrelated):
    later = PolicyRule("later", "allow", not_before=101)
    if unrelated == "different-action":
        later = replace(later, action="write_file")
    if unrelated == "nonmatching-params":
        later = replace(later, param_constraints={"cost": {"eq": 99, "required": True}})
    first = PolicyRule("first", "allow")
    rules = [first, later] if unrelated == "later-order" else [later, first]
    monitor, clock = runtime(rules=rules, default="deny")
    decision = monitor.evaluate(request())
    clock[0] = 101
    assert monitor.gateway.execute(decision.normalized_request, decision.permit).ok
    valid_bundle(monitor)


@pytest.mark.parametrize("time,allowed", [(100, True), (101, False), (102, False)])
def test_allow_expiry_boundary(time, allowed):
    monitor, clock = runtime(rules=[PolicyRule("allow", "allow", expires_at=101)], default="deny")
    decision = monitor.evaluate(request())
    assert decision.allowed and decision.permit.expires_at == 101
    clock[0] = time
    if allowed:
        assert monitor.gateway.execute(decision.normalized_request, decision.permit).ok
    else:
        with pytest.raises(PermitError):
            monitor.gateway.execute(decision.normalized_request, decision.permit)
        assert monitor.gateway.execution_count == 0


@pytest.mark.parametrize("kind", ["deny", "escalate", "emergency"])
def test_restriction_after_issuance_is_enforced(kind):
    if kind == "emergency":
        monitor, clock = runtime(emergency=EmergencyStop("actuator", 1))
        decision = monitor.evaluate(request())
        monitor.environment.state.actuator = 1
    else:
        monitor, clock = runtime(rules=[PolicyRule("new", kind, not_before=101)])
        decision = monitor.evaluate(request())
        clock[0] = 101
    with pytest.raises(PermitError):
        monitor.gateway.execute(decision.normalized_request, decision.permit)
    assert monitor.gateway.execution_count == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource", "/etc/forbidden"),
        ("subject", "other"),
        ("session_id", "other"),
        ("action", "secret_read"),
        ("nonce", "replacement"),
        ("params", {"value": 1}),
        ("context", {"x": 1}),
    ],
)
def test_permit_cannot_authorize_substituted_request(field, value):
    monitor, _ = runtime()
    decision = monitor.evaluate(request())
    with pytest.raises(PermitError):
        monitor.gateway.execute(replace(decision.normalized_request, **{field: value}), decision.permit)
    assert monitor.gateway.execution_count == 0
    assert monitor.gateway.execute(decision.normalized_request, decision.permit).ok


def test_parallel_permit_replay_has_one_effect_and_record():
    monitor, _ = runtime()
    decision = monitor.evaluate(request())
    barrier = Barrier(8)

    def execute():
        barrier.wait(timeout=5)
        try:
            return monitor.gateway.execute(decision.normalized_request, decision.permit).ok
        except PermitError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: execute(), range(8)))
    assert sum(results) == monitor.gateway.execution_count == len(monitor.evidence.events) == 1
    valid_bundle(monitor)


def test_reservations_are_not_charged_again_at_execution():
    rule = PolicyRule(
        "allow", "allow", rate_limit=RateLimit(2, 30), resource_budget=ResourceBudget("budget", "cost", 0.3)
    )
    monitor, _ = runtime(rules=[rule], default="deny")
    for index, cost in enumerate((0.1, 0.2)):
        decision, result = monitor.execute_request(request(params={"cost": cost}, nonce=str(index)))
        assert decision.allowed and result.ok
    assert monitor.policy_runtime.resource_usage["budget"] == Fraction(3, 10)
    assert monitor.capabilities.invocation_count("root") == 2
    assert not monitor.evaluate(request(nonce="over", params={"cost": 0.001})).allowed
    valid_bundle(monitor)


@pytest.mark.parametrize(
    "object_type", ["capability-input", "capability-get", "capability-clone", "policy-input", "policy-get"]
)
def test_nested_authority_copies_cannot_widen_values(object_type):
    proposed = request(params={"value": {"nested": [99]}})
    if object_type.startswith("capability"):
        values = {"value": {"enum": [{"nested": [1]}]}}
        store = CapabilityStore([Capability("root", "reviewer", "sandbox", "read_file", constraints=values)])
        exposed = (
            values
            if object_type == "capability-input"
            else (
                store.get("root").constraints
                if object_type == "capability-get"
                else store.clone().get("root").constraints
            )
        )
        exposed["value"]["enum"][0]["nested"][0] = 99
        assert not store.validate(proposed, 100, consume=False)[0]
    else:
        values = {"value": {"in": [{"nested": [1]}]}}
        policy = PolicyEngine(Policy("v", "deny", (PolicyRule("a", "allow", param_constraints=values),)))
        exposed = values if object_type == "policy-input" else policy.policy.rules[0].param_constraints
        exposed["value"]["in"][0]["nested"][0] = 99
        assert not policy.evaluate(proposed, RuntimeState(0, {}), now=100)[0]


@pytest.mark.parametrize("boolean,number", [(True, 1), (False, 0), ([True], [1]), ({"x": [False]}, {"x": [0]})])
def test_boolean_enum_and_delegation_cannot_gain_numeric_authority(boolean, number):
    parent = Capability(
        "root", "reviewer", "sandbox", "read_file", constraints={"value": {"enum": [number]}}, delegation_depth=1
    )
    child = replace(
        parent, capability_id="child", parent_id="root", delegation_depth=0, constraints={"value": {"enum": [boolean]}}
    )
    assert not capability_is_subset(child, parent)
    store = CapabilityStore([parent])
    assert not store.validate(request(params={"value": boolean}), 100, consume=False)[0]
    assert store.validate(request(params={"value": number}), 100, consume=False)[0]


@pytest.mark.parametrize("tamper", ["interior", "tail", "order", "duplicate", "payload", "checkpoint"])
def test_signed_evidence_detects_each_mutation(tamper):
    monitor, _ = runtime()
    for index in range(3):
        monitor.execute_request(request(nonce=str(index)))
    bundle = valid_bundle(monitor)
    if tamper == "interior":
        del bundle["events"][1]
    elif tamper == "tail":
        bundle["events"].pop()
    elif tamper == "order":
        bundle["events"].reverse()
    elif tamper == "duplicate":
        bundle["events"].append(deepcopy(bundle["events"][0]))
    elif tamper == "payload":
        bundle["events"][0]["requested_action"]["params"]["added"] = "tampered"
    else:
        bundle["checkpoint"]["event_count"] = 2
    assert not verify_evidence_bundle(bundle, monitor.public_key)[0]
    valid_bundle(monitor)


def test_wrong_trust_key_and_expected_manifest_rejected():
    monitor, _ = runtime()
    monitor.execute_request(request())
    bundle = valid_bundle(monitor)
    assert not verify_evidence_bundle(bundle, Ed25519PrivateKey.generate().public_key())[0]
    assert not verify_evidence_bundle(bundle, monitor.public_key, expected_manifest_hash="c" * 64)[0]


def test_evidence_snapshot_and_signed_manifest_are_detached():
    monitor, _ = runtime()
    monitor.execute_request(request(params={"value": {"nest": [1]}}))
    monitor.evidence.events[0].requested_action["params"]["value"]["nest"].append(2)
    valid_bundle(monitor)
    original = {"nested": [{"x": [1]}]}
    signed = sign_manifest(original, KEY)
    original["nested"][0]["x"].append(2)
    assert verify_manifest(signed, KEY.public_key())


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {"ok": True},
        ToolResult(1, "success"),
        ToolResult(True, "\ud800"),
        ToolResult(True, "x", {"nested": [float("nan")]}),
        ToolResult(True, "x", state_version=-1),
    ],
)
def test_bad_result_preserves_attempt_without_retry(bad):
    class Partial(SandboxEnvironment):
        def execute(self, proposed):
            self.state.actuator += 1
            return bad

    monitor, _ = runtime(environment=Partial())
    decision, result = monitor.execute_request(request())
    assert decision.allowed and result and result.ok is False
    assert len(monitor.evidence.events) == monitor.gateway.execution_count == monitor.environment.state.actuator == 1
    assert monitor.evidence.events[0].result_digest
    valid_bundle(monitor)
    with pytest.raises(PermitError):
        monitor.gateway.execute(decision.normalized_request, decision.permit)


@pytest.mark.parametrize(
    "name,value",
    [
        ("nonce", ""),
        ("tool", "Sandbox"),
        ("params", {"x": float("inf")}),
        ("context", {"x": "\udfff"}),
        ("observed_state_version", True),
    ],
)
def test_malformed_request_denial_does_not_consume_authority(name, value):
    monitor, _ = runtime()
    decision, result = monitor.execute_request(request(**{name: value}))
    assert not decision.allowed and result is None
    assert monitor.capabilities.invocation_count("root") == monitor.gateway.execution_count == 0
    valid_bundle(monitor)


@pytest.mark.parametrize("module", ["guardian_runtime.verifier.cli", "guardian_runtime.verifier.manifest_cli"])
@pytest.mark.parametrize("payload", ['{"x":1,"x":2}', "[1e999]", "[" * 129 + "]" * 129, '{"x":"\\ud800"}'])
def test_malformed_cli_input_has_nonzero_status_without_traceback(tmp_path, module, payload):
    path = tmp_path / "bad.json"
    path.write_text(payload, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", module, str(path), "--public-key", public_key_b64(KEY.public_key())],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode in (1, 2) and "Traceback" not in result.stderr
