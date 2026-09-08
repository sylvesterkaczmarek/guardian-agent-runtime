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
Invocation = Callable[[ActionRequest], Any]
Preparation = Callable[[], None]


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


def _measure_calls(invoke: Invocation, prepare: Preparation) -> dict[str, float | int]:
    for index in range(WARMUP):
        prepare()
        invoke(_request(-index - 1))

    values: list[float] = []
    for index in range(ITERATIONS):
        request = _request(index)
        prepare()
        start = time.perf_counter_ns()
        invoke(request)
        values.append((time.perf_counter_ns() - start) / 1e6)
    return _summary(values)


def _decision_invoker(architecture: str) -> tuple[Invocation, Preparation]:
    if architecture == "no_guardian":
        return (lambda request: True), (lambda: None)
    if architecture == "static_acl":
        allowed = set(DEFAULT_ACL)
        return (lambda request: (request.tool.strip().lower(), request.action.strip().lower()) in allowed), (lambda: None)

    return _guardian_invoker(architecture, end_to_end=False)


def _guardian_invoker(architecture: str, *, end_to_end: bool) -> tuple[Invocation, Preparation]:
    if architecture not in {"guardian_initial", "guardian_hardened"}:
        raise ValueError(f"unknown architecture: {architecture}")

    runtime, _, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
    calls = 0

    def prepare() -> None:
        nonlocal runtime, calls
        if calls >= 90:
            runtime, _, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
            calls = 0

    def invoke(request: ActionRequest):
        nonlocal calls
        calls += 1
        if end_to_end:
            return runtime.execute_request(request)
        return runtime.evaluate(request)

    return invoke, prepare


def _end_to_end_invoker(architecture: str) -> tuple[Invocation, Preparation]:
    if architecture == "no_guardian":
        runner = NoGuardianRunner(MissionEnvironment())
        return runner.execute, (lambda: None)
    if architecture == "static_acl":
        acl_runner = StaticACLRunner(MissionEnvironment(), DEFAULT_ACL)
        return acl_runner.execute, (lambda: None)

    return _guardian_invoker(architecture, end_to_end=True)


def measure(architecture: str) -> dict[str, dict[str, float | int]]:
    return {
        "decision_path": _measure_calls(*_decision_invoker(architecture)),
        "end_to_end_request": _measure_calls(*_end_to_end_invoker(architecture)),
    }


def main() -> int:
    output = ROOT / "results" / "local" / "latency_summary.json"
    payload = {
        "note": (
            "Host-dependent measurements; excluded from deterministic reference checksums. "
            "Decision-path timing measures authorization only. Request construction and "
            "periodic runtime preparation are excluded from both timed paths."
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
