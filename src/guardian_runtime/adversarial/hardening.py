from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from collections.abc import Iterable
from typing import Any

import yaml

from guardian_runtime.adversarial.attacks import (
    Scenario,
    attack_scenarios,
    benign_scenarios,
    generated_attack_scenarios,
    run_attack_scenario,
    run_benign_scenario,
)
from guardian_runtime.factory import reference_config_path
from guardian_runtime.yamlutil import load_yaml_unique


HARDENING_SEARCH_SEED = 20260808
HARDENING_SEARCH_COUNT = 36


def _scenario_succeeds(architecture: str, scenario: Scenario) -> bool:
    return run_attack_scenario(architecture, scenario).attack_success


def minimize_scenario_trace(scenario: Scenario, architecture: str = "guardian_initial") -> Scenario:
    """Greedily remove requests while preserving the bypass.

    The current discovered proxy bypasses are one-step traces, but keeping an executable
    minimizer here makes multi-step future bypasses produce smaller regression cases.
    """

    current = scenario
    changed = True
    while changed and len(current.requests) > 1:
        changed = False
        for index in range(len(current.requests)):
            candidate_requests = current.requests[:index] + current.requests[index + 1 :]
            if not candidate_requests:
                continue
            candidate = replace(current, requests=candidate_requests)
            if _scenario_succeeds(architecture, candidate):
                current = candidate
                changed = True
                break
    return current


def _trace_fingerprint(scenario: Scenario) -> tuple[Any, ...]:
    if not scenario.requests:
        return (scenario.mode, scenario.name)
    request = scenario.requests[0]
    target = request.params.get("target") if isinstance(request.params, dict) else None
    return (scenario.domain, request.tool, request.action, target, scenario.mode)


def _serialize_scenario(scenario: Scenario) -> dict[str, Any]:
    return {
        "name": scenario.name,
        "domain": scenario.domain,
        "mode": scenario.mode,
        "scenario_class": scenario.scenario_class,
        "notes": scenario.notes,
        "max_allowed": scenario.max_allowed,
        "requests": [request.to_dict() for request in scenario.requests],
    }


def _deduplicate_traces(scenarios: Iterable[Scenario]) -> list[Scenario]:
    selected: dict[tuple[Any, ...], Scenario] = {}
    for scenario in scenarios:
        selected.setdefault(_trace_fingerprint(scenario), scenario)
    return list(selected.values())


def _benign_proxy_contracts() -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    for scenario in benign_scenarios():
        for request in scenario.requests:
            if request.tool != "sandbox" or request.action != "proxy_call":
                continue
            contracts.append(
                {
                    "target": request.params.get("target"),
                    "nested_capability_id": request.params.get("nested_capability_id"),
                    "target_resource": request.params.get("target_resource"),
                }
            )
    return contracts


def _propose_defense(minimized: list[Scenario]) -> dict[str, Any] | None:
    proxy_bypasses = [
        scenario
        for scenario in minimized
        if scenario.requests
        and scenario.requests[0].tool == "sandbox"
        and scenario.requests[0].action == "proxy_call"
    ]
    if not proxy_bypasses:
        return None

    observed_targets = sorted(
        {
            str(scenario.requests[0].params.get("target"))
            for scenario in proxy_bypasses
            if isinstance(scenario.requests[0].params.get("target"), str)
        }
    )
    benign_contracts = _benign_proxy_contracts()
    if not benign_contracts:
        return None

    # The synthesis step deliberately does not enumerate a blacklist of observed bad
    # targets. It infers that proxy_call is an authority-composition boundary and changes
    # the architecture so every nested action must carry its own capability and re-enter
    # Guardian authorization. The benign traces are used only to verify that at least one
    # legitimate composition contract remains representable.
    return {
        "policy_rule": "allow-proxy-mediated",
        "change": (
            "Require every proxy target to carry an explicit nested capability and re-enter Guardian authorization."
        ),
        "rationale": (
            "Outer proxy authority must not stand in for the authority required by a nested privileged action."
        ),
        "observed_proxy_targets": observed_targets,
        "benign_proxy_contracts": benign_contracts,
        "runtime_change": "recursive-guardian-mediation",
        "reviewed_policy": "configs/guardian/hardened.yaml",
    }


def _benign_completion(architecture: str, *, policy_path: Path | None = None) -> float:
    outcomes = [
        run_benign_scenario(architecture, case, policy_path=policy_path).allowed_count > 0
        for case in benign_scenarios()
    ]
    return sum(outcomes) / len(outcomes)


def _candidate_policy(proposal: dict[str, Any]) -> dict[str, Any]:
    initial = load_yaml_unique(reference_config_path("guardian", "initial.yaml").read_text(encoding="utf-8"))
    if not isinstance(initial, dict) or not isinstance(initial.get("rules"), list):
        raise ValueError("initial policy is malformed")
    candidate = dict(initial)
    candidate["version"] = "1.2-hardened"
    mediated_proxy_rule = {
        "id": proposal["policy_rule"],
        "effect": "allow",
        "tool": "sandbox",
        "action": "proxy_call",
        "params": {
            "target": {"required": True},
            "target_params": {"required": True},
            "target_resource": {"required": True, "canonical_resource": True},
            "nested_capability_id": {"required": True},
        },
    }
    candidate["rules"] = [
        mediated_proxy_rule if rule.get("id") == "allow-proxy" else rule
        for rule in initial["rules"]
    ]
    return candidate


def run_self_hardening() -> dict[str, Any]:
    search_cases = list(attack_scenarios()) + list(
        generated_attack_scenarios(HARDENING_SEARCH_SEED, count=HARDENING_SEARCH_COUNT)
    )
    initial_results = [run_attack_scenario("guardian_initial", case) for case in search_cases]
    bypass_cases = [case for case, result in zip(search_cases, initial_results, strict=True) if result.attack_success]
    minimized = [minimize_scenario_trace(case) for case in bypass_cases]
    regression_cases = _deduplicate_traces(minimized)
    proposal = _propose_defense(minimized)

    benign_before = _benign_completion("guardian_initial")
    hardened_results = []
    benign_after = benign_before
    reviewed_policy_matches_candidate = False

    if proposal is not None:
        candidate_data = _candidate_policy(proposal)
        reviewed_data = load_yaml_unique(
            reference_config_path("guardian", "hardened.yaml").read_text(encoding="utf-8")
        )
        reviewed_policy_matches_candidate = candidate_data == reviewed_data
        with TemporaryDirectory(prefix="guardian-hardening-") as tmpdir:
            candidate_path = Path(tmpdir) / "candidate.yaml"
            candidate_path.write_text(
                yaml.safe_dump(candidate_data, sort_keys=False),
                encoding="utf-8",
            )
            hardened_results = [
                run_attack_scenario("guardian_hardened", case, policy_path=candidate_path)
                for case in search_cases
            ]
            benign_after = _benign_completion("guardian_hardened", policy_path=candidate_path)

    remaining = [
        case.name
        for case, result in zip(search_cases, hardened_results, strict=True)
        if result.attack_success
    ]
    eliminated = [
        case.name
        for case, before, after in zip(search_cases, initial_results, hardened_results, strict=True)
        if before.attack_success and not after.attack_success
    ]
    new_failures = [
        case.name
        for case, before, after in zip(search_cases, initial_results, hardened_results, strict=True)
        if not before.attack_success and after.attack_success
    ]

    utility_degradation = benign_before - benign_after
    retained = (
        bool(proposal)
        and bool(eliminated)
        and not remaining
        and not new_failures
        and utility_degradation <= 0.0
        and reviewed_policy_matches_candidate
    )

    history = []
    if proposal is not None:
        history.append(
            {
                **proposal,
                "bypasses_reproduced": [case.name for case in bypass_cases],
                "minimized_traces": [_serialize_scenario(case) for case in regression_cases],
                "attack_successes_before": sum(result.attack_success for result in initial_results),
                "attack_successes_after": sum(result.attack_success for result in hardened_results),
                "benign_completion_before": benign_before,
                "benign_completion_after": benign_after,
                "utility_degradation": utility_degradation,
                "new_failures_after_hardening": new_failures,
                "candidate_policy_matches_reviewed_policy": reviewed_policy_matches_candidate,
                "retained": retained,
            }
        )

    return {
        "search": {
            "fixed_cases": len(attack_scenarios()),
            "generated_seed": HARDENING_SEARCH_SEED,
            "generated_cases": HARDENING_SEARCH_COUNT,
        },
        "initial_bypasses": [case.name for case in bypass_cases],
        "proposed_changes": [proposal] if proposal else [],
        "history": history,
        "regression_cases": [_serialize_scenario(case) for case in regression_cases] if retained else [],
        "eliminated_bypasses": eliminated if retained else [],
        "remaining_bypasses": remaining,
        "benign_completion_before": benign_before,
        "benign_completion_after": benign_after,
        "utility_degradation": utility_degradation,
    }


def discovered_regression_cases() -> tuple[str, ...]:
    return tuple(item["name"] for item in run_self_hardening()["regression_cases"])
