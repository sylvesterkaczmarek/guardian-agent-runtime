from __future__ import annotations

import json
import platform
import statistics
import time
from collections.abc import Callable
from typing import Any

from guardian_runtime.adversarial import ARCHITECTURES
from guardian_runtime.baselines import DEFAULT_ACL, NoGuardianRunner, StaticACLRunner
from guardian_runtime.factory import ROOT, build_guardian
from guardian_runtime.simulator import MissionEnvironment
from guardian_runtime.types import ActionRequest


WARMUP = 20
ITERATIONS = 200


def _request(index: int) -> ActionRequest:
    return ActionRequest(
        subject="agent-1",
        session_id="latency",
        tool="mission",
        action="observe_telemetry",
        purpose="operations",
        capability_id="cap-observe",
        nonce=f"latency-{index}",
    )


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def _summary(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "mean_ms": statistics.fmean(values),
        "median_ms": statistics.median(values),
        "p95_ms": _percentile(values, 0.95),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def _measure_calls(invoke: Callable[[ActionRequest], Any]) -> dict[str, float | int]:
    for index in range(WARMUP):
        invoke(_request(-index - 1))

    values: list[float] = []
    for index in range(ITERATIONS):
        start = time.perf_counter_ns()
        invoke(_request(index))
        values.append((time.perf_counter_ns() - start) / 1e6)
    return _summary(values)


def _decision_invoker(architecture: str) -> Callable[[ActionRequest], Any]:
    if architecture == "no_guardian":
        return lambda request: True
    if architecture == "static_acl":
        allowed = set(DEFAULT_ACL)
        return lambda request: (request.tool.strip().lower(), request.action.strip().lower()) in allowed

    runtime, _, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
    calls = 0

    def invoke(request: ActionRequest):
        nonlocal runtime, calls
        if calls >= 90:
            runtime, _, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
            calls = 0
        calls += 1
        return runtime.evaluate(request)

    return invoke


def _end_to_end_invoker(architecture: str) -> Callable[[ActionRequest], Any]:
    if architecture == "no_guardian":
        runner = NoGuardianRunner(MissionEnvironment())
        return runner.execute
    if architecture == "static_acl":
        runner = StaticACLRunner(MissionEnvironment(), DEFAULT_ACL)
        return runner.execute

    runtime, _, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
    calls = 0

    def invoke(request: ActionRequest):
        nonlocal runtime, calls
        if calls >= 90:
            runtime, _, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
            calls = 0
        calls += 1
        return runtime.execute_request(request)

    return invoke


def measure(architecture: str) -> dict[str, dict[str, float | int]]:
    return {
        "decision_path": _measure_calls(_decision_invoker(architecture)),
        "end_to_end_request": _measure_calls(_end_to_end_invoker(architecture)),
    }


def main() -> int:
    output = ROOT / "results" / "local" / "latency_summary.json"
    payload = {
        "note": (
            "Host-dependent measurements; excluded from deterministic reference checksums. "
            "Decision-path timing measures authorization only."
        ),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "warmup": WARMUP,
        "iterations": ITERATIONS,
        "architectures": {architecture: measure(architecture) for architecture in ARCHITECTURES},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
