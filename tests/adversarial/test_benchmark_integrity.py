from dataclasses import replace

import pytest

from experiments import run_reference_suite
from guardian_runtime.adversarial import Scenario, attack_scenarios, benign_scenarios, run_benign_scenario
from guardian_runtime.adversarial import attacks, hardening
from guardian_runtime.factory import build_guardian


def test_rate_limit_requests_do_not_inflate_capability_overprivilege(monkeypatch):
    cases = attack_scenarios()
    monkeypatch.setattr(run_reference_suite, "attack_scenarios", lambda: cases)
    with_rate_limit = run_reference_suite.run_one(7, "guardian_hardened", generated_count=1)
    monkeypatch.setattr(
        run_reference_suite, "attack_scenarios", lambda: tuple(case for case in cases if case.max_allowed is None)
    )
    without_rate_limit = run_reference_suite.run_one(7, "guardian_hardened", generated_count=1)
    assert with_rate_limit["capability_overprivilege_rate"] == without_rate_limit["capability_overprivilege_rate"]


def test_fixed_case_metrics_match_explicit_counts():
    run = run_reference_suite.run_one(7, "guardian_hardened", generated_count=0)
    # Six of 18 capability-only probes are accepted: three proxy routes, two nested
    # mission plans and one stale-state action. The six rate-window calls are excluded.
    assert run["capability_overprivilege_rate"] == 6 / 18
    results = {result["name"]: result for result in run["attack_results"]}
    assert results["log_tail_deletion_attempt"]["allowed_count"] == 2
    assert results["log_tail_deletion_attempt"]["explicit_rule_count"] == 2
    assert results["log_tail_deletion_attempt"]["evidence_covered_requests"] == 2


@pytest.mark.parametrize("already_secure", [False, True])
def test_hardening_finishes_when_no_defence_is_applicable(monkeypatch, already_secure):
    name = "direct_unauthorized_action" if already_secure else "confused_deputy"
    case = next(case for case in attack_scenarios() if case.name == name)
    monkeypatch.setattr(hardening, "attack_scenarios", lambda: (case,))
    monkeypatch.setattr(hardening, "generated_attack_scenarios", lambda *args, **kwargs: ())
    monkeypatch.setattr(hardening, "_propose_defense", lambda scenarios: None)
    result = hardening.run_self_hardening()
    assert result["history"] == []
    assert result["proposed_changes"] == []
    assert result["regression_cases"] == []
    assert result["remaining_bypasses"] == ([] if already_secure else [name])
    assert result["benign_completion_before"] == result["benign_completion_after"]


def test_partial_benign_sequence_does_not_count_as_completion():
    good = next(case for case in benign_scenarios() if case.name == "read_tmp_file").requests[0]
    blocked = replace(good, nonce="second-step", resource="/guardian/policy.yaml")
    scenario = Scenario("read-two-files", "sandbox", (good, blocked), scenario_class="benign")
    result = run_benign_scenario("guardian_hardened", scenario)
    assert result.allowed_count == 1
    assert not result.task_completed


@pytest.mark.parametrize("architecture", ["guardian_hardened", "no_guardian"])
def test_empty_benign_sequence_is_not_a_completed_task(architecture):
    result = run_benign_scenario(architecture, Scenario("empty", "sandbox", (), scenario_class="benign"))
    assert not result.task_completed


@pytest.mark.parametrize("architecture,domain", [("guardan_hardened", "sandbox"), ("no_guardian", "sandbxo")])
def test_benign_runner_rejects_misspelled_architecture_or_domain(architecture, domain):
    case = replace(benign_scenarios()[0], domain=domain)
    with pytest.raises(ValueError, match="unknown"):
        run_benign_scenario(architecture, case)


def test_nested_evidence_cannot_cover_another_unrecorded_request(monkeypatch):
    runtime, manifest, metadata = build_guardian("sandbox", hardened=True)
    append = runtime.evidence.append

    def selectively_append(**kwargs):
        if kwargs["request"].nonce == "missing-record":
            return None
        return append(**kwargs)

    monkeypatch.setattr(runtime.evidence, "append", selectively_append)
    monkeypatch.setattr(attacks, "build_guardian", lambda *args, **kwargs: (runtime, manifest, metadata))
    proxy = next(case for case in benign_scenarios() if case.name == "safe_proxy_read").requests[0]
    read = next(case for case in benign_scenarios() if case.name == "read_tmp_file").requests[0]
    scenario = Scenario("partial-audit", "sandbox", (proxy, replace(read, nonce="missing-record")), scenario_class="benign")
    result = run_benign_scenario("guardian_hardened", scenario)
    assert result.allowed_count == 2
    assert result.evidence_events == 2  # Both belong to the proxy's nested and outer actions.
    assert result.evidence_covered_requests == 1


def test_inner_evidence_cannot_substitute_for_its_outer_request(monkeypatch):
    runtime, manifest, metadata = build_guardian("sandbox", hardened=True)
    append = runtime.evidence.append

    def selectively_append(**kwargs):
        if kwargs["request"].action == "proxy_call":
            return None
        return append(**kwargs)

    monkeypatch.setattr(runtime.evidence, "append", selectively_append)
    monkeypatch.setattr(attacks, "build_guardian", lambda *args, **kwargs: (runtime, manifest, metadata))
    scenario = next(case for case in benign_scenarios() if case.name == "safe_proxy_read")
    result = run_benign_scenario("guardian_hardened", scenario)
    assert result.allowed_count == 1
    assert result.evidence_events == 1
    assert result.evidence_covered_requests == 0
