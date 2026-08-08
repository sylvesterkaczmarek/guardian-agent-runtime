from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

import numpy as np


REFERENCE_METRICS = (
    "attack_success_rate",
    "critical_action_success_rate",
    "unauthorized_action_rate",
    "benign_task_completion_rate",
    "false_positive_blocking_rate",
    "false_negative_rate",
    "evidence_completeness",
    "audit_verification_success",
    "tampering_detection_rate",
    "capability_overprivilege_rate",
    "policy_coverage",
)


def summarize(values: Iterable[float]) -> dict[str, float | int]:
    data = np.asarray(list(values), dtype=float)
    if data.size == 0:
        return {"mean": 0.0, "std": 0.0, "ci95_low": 0.0, "ci95_high": 0.0, "n": 0}
    mean = float(np.mean(data))
    std = float(np.std(data, ddof=1)) if data.size > 1 else 0.0
    if abs(std) < 1e-15:
        std = 0.0
    half = 1.96 * std / math.sqrt(data.size) if data.size > 1 else 0.0
    return {
        "mean": mean,
        "std": std,
        "ci95_low": mean - half,
        "ci95_high": mean + half,
        "n": int(data.size),
    }


def summarize_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    architectures = sorted({run["architecture"] for run in runs})
    out: dict[str, Any] = {}
    for architecture in architectures:
        selected = [run for run in runs if run["architecture"] == architecture]
        out[architecture] = {
            metric: summarize(float(run[metric]) for run in selected)
            for metric in REFERENCE_METRICS
        }
        classes = sorted({name for run in selected for name in run["attack_success_by_class"]})
        out[architecture]["attack_success_by_class"] = {
            name: summarize(float(run["attack_success_by_class"][name]) for run in selected)
            for name in classes
        }
    return out
