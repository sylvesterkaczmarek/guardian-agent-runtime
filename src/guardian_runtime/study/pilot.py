"""Reproducible paired case-level observations; timing is opt-in and host-specific."""
from __future__ import annotations

from dataclasses import asdict, replace
from math import ceil
from time import perf_counter_ns

from guardian_runtime.crypto import public_key_b64
from guardian_runtime.study.reference_controls import reference_outcomes
from guardian_runtime.study.scoring import simple_checker, verify_claims
from guardian_runtime.study.workflows import CLAIMS, FAMILIES, MODES, StudyEnvironment, proposal

VIEWS = ("acknowledgement", "terminal", "trajectory")


def execute_guardian(family, mode, view, request, *, ready=True):
    env = StudyEnvironment(family, mode, ready=ready, view=view)
    runtime, manifest, _ = env.runtime()
    start = perf_counter_ns()
    decision, result = runtime.execute_request(request)
    elapsed = perf_counter_ns() - start
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    return env, decision, result, bundle, manifest, runtime.public_key, elapsed


def state_gateway(family, mode, request, *, ready=True):
    """Same state, per-step parameter envelope and allowed operation identities, no signing."""
    env = StudyEnvironment(family, mode, ready=ready)
    start = perf_counter_ns()
    allowed = request == proposal(family, request.params.get("target")) and env.check_invariants(request)[0]
    if allowed:
        for child in env.build_nested_requests(request):
            if child.action not in {"prepare", "apply"} or not env.check_invariants(child)[0]:
                allowed = False
                break
            if not env.execute(child).ok:
                break
    return env, allowed, perf_counter_ns() - start


def _truth(history, goal):
    return dict(zip(CLAIMS, (history[-1] == goal, 0 <= history[-1] <= 5, all(0 <= x <= 5 for x in history)), strict=True))


def predictions(mode, view):
    # Frozen protocol, independent of scorer outputs. A visible violation refutes
    # the trajectory claim even with incomplete coverage.
    final = view != "acknowledgement" and mode not in {"missing", "delayed"}
    trajectory = final and (view == "trajectory" or mode == "wrong_final")
    return dict(zip(CLAIMS, (final, final, trajectory), strict=True))


def summarize(rows):
    metrics = {}
    for method in ("acknowledgement", "simple_checker", "guardian"):
        totals = dict(claims=0, actual_violations=0, false_confirmations=0, false_denials=0, missed_violations=0,
                      unknown=0, predicted_answerable=0, correctly_resolved_answerable=0)
        for row in rows:
            for claim, truth in row["truth"].items():
                verdict = row["verdicts"][method][claim]
                totals["claims"] += 1
                totals["actual_violations"] += not truth
                totals["false_confirmations"] += verdict is True and not truth
                totals["false_denials"] += verdict is False and truth
                totals["missed_violations"] += not truth and verdict is not False
                totals["unknown"] += verdict is None
                if row["answerable"][claim]:
                    totals["predicted_answerable"] += 1
                    totals["correctly_resolved_answerable"] += verdict is truth
        metrics[method] = totals
    return metrics


def run_pilot(*, timing=False):
    rows = []
    samples = {}
    timing_samples: dict[str, list[float]] = {}
    prevention = []
    for family, (_, _, goal) in FAMILIES.items():
        request = proposal(family)
        for mode in MODES:
            for view in VIEWS:
                env, decision, result, bundle, manifest, key, elapsed = execute_guardian(family, mode, view, request)
                baseline, baseline_allowed, baseline_ns = state_gateway(family, mode, request)
                if not decision.allowed or result is None:
                    raise RuntimeError("valid study workflow was refused")
                readings = env.read_observer(replace(request, action="apply"), result)
                start = perf_counter_ns()
                signed = verify_claims(bundle, key, manifest.manifest_hash, request, f"{family}-{view}", goal)
                verify_ns = perf_counter_ns() - start
                truth = _truth(env.commits, goal)
                rows.append({
                    "family": family, "mode": mode, "view": view, "truth": truth, "answerable": predictions(mode, view),
                    "observations": readings, "tool_ok": result.ok, "tool_status": result.status,
                    "actual_commits": env.commits, "baseline_commits": baseline.commits, "baseline_admitted": baseline_allowed,
                    "truth_agrees_across_executions": truth == _truth(baseline.commits, goal),
                    "verdicts": {"acknowledgement": {"completion": result.ok, "endpoint_in_range": None, "trajectory_in_range": None},
                                 "simple_checker": simple_checker(readings, goal), "guardian": signed},
                })
                if mode == "normal" and view == "trajectory":
                    samples[family] = {"manifest": asdict(manifest), "public_key": public_key_b64(key), "bundle": bundle}
                for name, ns in (("guardian_execution", elapsed), ("gateway_execution", baseline_ns), ("verification", verify_ns)):
                    timing_samples.setdefault(f"{family}.{name}", []).append(ns / 1e6)
                timing_samples.setdefault(f"{family}.paired_overhead", []).append((elapsed - baseline_ns) / 1e6)
        for control, target, ready in [("out_of_range", 7, True), ("unready", goal, False)]:
            req = proposal(family, target)
            guarded, dec, _, _, _, _, _ = execute_guardian(family, "normal", "trajectory", req, ready=ready)
            baseline, admitted, _ = state_gateway(family, "normal", req, ready=ready)
            prevention.append({"family": family, "condition": control, "guardian_admitted": dec.allowed,
                               "gateway_admitted": admitted, "guardian_invocations": guarded.invocations,
                               "gateway_invocations": baseline.invocations})
    summary = {}
    for family in FAMILIES:
        selected = [r for r in rows if r["family"] == family]
        # One execution condition per mode for utility; observer projections are not additional workflows.
        normal = [r for r in selected if r["view"] == "trajectory" and r["mode"] == "normal"]
        summary[family] = {"by_method": summarize(selected), "normal_tasks": len(normal),
                           "guardian_normal_completed": sum(r["truth"]["completion"] for r in normal),
                           "gateway_normal_completed": sum(r["baseline_commits"][-1] == FAMILIES[family][2] for r in normal),
                           "by_view": {v: summarize([r for r in selected if r["view"] == v]) for v in VIEWS}}
    report = {"schema_version": 1, "study": "observation-contract-pilot", "rows": rows, "summary": summary,
              "prevention_controls": prevention, "independent_implementations_per_family": 1,
              "population_interval": None, "reference_benign_controls": reference_outcomes()}
    if timing:
        import platform
        report["timing_host"] = {"python": platform.python_version(), "system": platform.platform(),
                                 "units": "ms", "includes": "synchronous dispatch through tool return; excludes runtime construction"}
        report["timing_ms"] = {k: {"n": len(v), "p95": sorted(v)[ceil(.95 * len(v)) - 1]} for k, v in timing_samples.items()}
    return report, samples
