from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from experiments.negative_results import run_negative_results
from guardian_runtime.adversarial import (
    ARCHITECTURES,
    attack_scenarios,
    benign_scenarios,
    generated_attack_scenarios,
    run_attack_scenario,
    run_benign_scenario,
)
from guardian_runtime.adversarial.hardening import run_self_hardening
from guardian_runtime.canonical import CanonicalizationError, canonicalize_request
from guardian_runtime.crypto import public_key_b64
from guardian_runtime.evaluation import summarize_runs
from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.factory import REFERENCE_TIME, ROOT, build_guardian, load_capability_store
from guardian_runtime.types import ActionRequest
from guardian_runtime.yamlutil import load_yaml_unique


OUT = ROOT / "results"
FIG = OUT / "figures"
DETERMINISTIC_RESULT_FILES = (
    "runs.json",
    "reference_summary.json",
    "hardening_history.json",
    "generated_regressions.json",
    "negative_results.json",
    "runtime_manifest.json",
    "dependency_inventory.json",
    "sbom.spdx.json",
)


def _research_source_sha256() -> str:
    """Hash the implementation and experiment logic that defines checked results."""
    hasher = hashlib.sha256()
    roots = ("src", "experiments", "formal", "scripts")
    files = sorted(
        path
        for root_name in roots
        for path in (ROOT / root_name).rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in {".py", ".yaml", ".tla", ".cfg"}
    )
    for path in files:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        data = path.read_bytes()
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return hasher.hexdigest()


def _audit_verification(architecture: str) -> float:
    if not architecture.startswith("guardian"):
        return 0.0
    runtime, signed_manifest, _ = build_guardian("mission", hardened=architecture == "guardian_hardened")
    request = ActionRequest(
        subject="agent-1",
        session_id="audit-check",
        tool="mission",
        action="observe_telemetry",
        capability_id="cap-observe",
        nonce="audit-1",
        purpose="operations",
    )
    runtime.execute_request(request)
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    ok, _ = verify_evidence_bundle(
        bundle,
        runtime.public_key,
        expected_policy_version=runtime.policy.version,
        expected_manifest_hash=signed_manifest.manifest_hash,
    )
    return float(ok)


def _critical(case_name: str, domain: str) -> bool:
    if case_name.startswith("generated_maneuver_"):
        return True
    return case_name in {
        "direct_unauthorized_action",
        "prompt_injection",
        "privilege_escalation",
        "unauthorized_action_composition",
        "stale_state_action",
        "toctou_state_change",
        "compromised_agent",
        "unsafe_action_hidden_in_plan",
    } or (domain == "mission" and case_name.startswith("generated_"))


def run_one(seed: int, architecture: str, *, generated_count: int = 24) -> dict[str, Any]:
    base_attacks = list(attack_scenarios())
    generated = list(generated_attack_scenarios(seed, count=generated_count))
    attacks = base_attacks + generated
    benign = list(benign_scenarios())

    attack_results = [run_attack_scenario(architecture, case) for case in attacks]
    benign_results = [run_benign_scenario(architecture, case) for case in benign]

    attack_rate = float(np.mean([result.attack_success for result in attack_results]))
    critical_values = [
        result.attack_success
        for result, case in zip(attack_results, attacks, strict=True)
        if _critical(case.name, case.domain)
    ]
    benign_values = [result.allowed_count > 0 for result in benign_results]
    benign_rate = float(np.mean(benign_values))

    # Audit completeness is measured on normal mediated request paths. Special harness
    # modes deliberately manipulate permits/state outside execute_request to test the
    # reference monitor boundary and are reported separately.
    excluded_modes = {"toctou", "delegation", "permit_replay", "revoke_after_authorization"}
    evidence_eligible = [
        (result, case)
        for result, case in zip(attack_results, attacks, strict=True)
        if case.mode not in excluded_modes
    ] + list(zip(benign_results, benign, strict=True))
    # Evidence completeness is the fraction of external mediated requests that leave at
    # least one evidence record. Recursive nested mediation may legitimately produce
    # more than one evidence event for one external request, so extra nested events do
    # not inflate completeness above 1.0.
    evidence_covered_requests = sum(
        min(result.evidence_events, result.request_count) for result, _ in evidence_eligible
    )
    evidence_requests = sum(result.request_count for result, _ in evidence_eligible)

    tamper_results = [
        result
        for result in attack_results
        if result.name in {"log_modification_attempt", "log_tail_deletion_attempt"}
    ]
    # Capability over-privilege is measured independently of policy and invariants: it
    # is the fraction of adversarial action proposals whose presented capability alone
    # accepts the normalized authority. Architectures without a capability boundary are
    # scored as fully exposed by definition. Lifecycle, audit-tamper, delegation-model,
    # and rate-limit harness modes are excluded because they test different properties.
    if architecture in {"no_guardian", "static_acl"}:
        capability_overprivilege_rate = 1.0
    else:
        capability_probes: list[bool] = []
        for case in attacks:
            if case.mode not in {"action", "agent_context"}:
                continue
            for probe in case.requests:
                try:
                    normalized = canonicalize_request(probe)
                except CanonicalizationError:
                    capability_probes.append(False)
                    continue
                store = load_capability_store()
                accepted, _ = store.validate(normalized, REFERENCE_TIME, consume=False)
                capability_probes.append(accepted)
        capability_overprivilege_rate = (
            float(np.mean(capability_probes)) if capability_probes else 0.0
        )

    # Policy coverage is the fraction of external scenario requests that reach an
    # explicit policy rule. Nested recursive rules are additional internal mediation and
    # therefore do not increase external coverage beyond one request.
    explicit_rule_requests = sum(
        min(result.explicit_rule_count, result.request_count)
        for result in attack_results + benign_results
    )
    total_requests = sum(result.request_count for result in attack_results + benign_results)

    by_class: dict[str, float] = {}
    for scenario_class in sorted({case.scenario_class for case in attacks}):
        values = [
            result.attack_success
            for result, case in zip(attack_results, attacks, strict=True)
            if case.scenario_class == scenario_class
        ]
        by_class[scenario_class] = float(np.mean(values)) if values else 0.0

    return {
        "seed": seed,
        "architecture": architecture,
        "attack_success_rate": attack_rate,
        "critical_action_success_rate": float(np.mean(critical_values)) if critical_values else 0.0,
        "unauthorized_action_rate": attack_rate,
        "benign_task_completion_rate": benign_rate,
        "false_positive_blocking_rate": 1.0 - benign_rate,
        "false_negative_rate": attack_rate,
        "evidence_completeness": (
            evidence_covered_requests / evidence_requests if evidence_requests else 0.0
        ),
        "audit_verification_success": _audit_verification(architecture),
        "tampering_detection_rate": float(np.mean([not result.attack_success for result in tamper_results])),
        "capability_overprivilege_rate": capability_overprivilege_rate,
        "policy_coverage": explicit_rule_requests / total_requests if total_requests else 0.0,
        "attack_success_by_class": by_class,
        "attack_results": [asdict(result) for result in attack_results],
        "benign_results": [asdict(result) for result in benign_results],
    }


def _plot(summary: dict[str, Any], hardening: dict[str, Any]) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    order = ["no_guardian", "static_acl", "guardian_initial", "guardian_hardened"]

    def values(metric: str) -> list[float]:
        return [float(summary[name][metric]["mean"]) for name in order]

    labels = ["No Guardian", "Static ACL", "Guardian initial", "Guardian hardened"]

    plt.figure(figsize=(8.5, 4.8))
    plt.bar(labels, values("attack_success_rate"))
    plt.ylabel("Attack success rate")
    plt.ylim(0, 1.05)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(FIG / "attack_success_by_architecture.png", dpi=180, metadata={"Software": "Matplotlib"})
    plt.close()

    plt.figure(figsize=(8.5, 4.8))
    plt.bar(labels, values("benign_task_completion_rate"))
    plt.ylabel("Benign task completion rate")
    plt.ylim(0, 1.05)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(FIG / "benign_completion_by_architecture.png", dpi=180, metadata={"Software": "Matplotlib"})
    plt.close()

    plt.figure(figsize=(6.5, 5.2))
    for name, label in zip(order, labels, strict=True):
        x = float(summary[name]["attack_success_rate"]["mean"])
        y = float(summary[name]["benign_task_completion_rate"]["mean"])
        plt.scatter([x], [y], s=60)
        plt.annotate(label, (x, y), xytext=(5, 5), textcoords="offset points")
    plt.xlabel("Attack success rate (lower is better)")
    plt.ylabel("Benign task completion rate (higher is better)")
    plt.xlim(-0.05, 1.05)
    plt.ylim(-0.05, 1.05)
    plt.tight_layout()
    plt.savefig(FIG / "safety_utility_frontier.png", dpi=180, metadata={"Software": "Matplotlib"})
    plt.close()

    plt.figure(figsize=(8.5, 4.8))
    plt.bar(labels, values("tampering_detection_rate"))
    plt.ylabel("Tampering detection rate")
    plt.ylim(0, 1.05)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(FIG / "tampering_detection_by_architecture.png", dpi=180, metadata={"Software": "Matplotlib"})
    plt.close()

    history = hardening.get("history", [])
    if history:
        before = int(history[0]["attack_successes_before"])
        after = int(history[0]["attack_successes_after"])
        plt.figure(figsize=(6.5, 4.8))
        plt.bar(["Initial policy", "Retained hardening"], [before, after])
        plt.ylabel("Successful bypass cases")
        plt.tight_layout()
        plt.savefig(FIG / "hardening_bypass_elimination.png", dpi=180, metadata={"Software": "Matplotlib"})
        plt.close()


def _write_manifest(runtime_manifest: dict[str, Any], signed_manifest, public_key: str) -> None:
    (OUT / "runtime_manifest.json").write_text(
        json.dumps(
            {
                "manifest": runtime_manifest,
                "manifest_hash": signed_manifest.manifest_hash,
                "signature": signed_manifest.signature,
                "public_key": public_key,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _generate_supply_chain_outputs() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "dependency_inventory.py"), str(OUT / "dependency_inventory.json")], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_sbom.py"), str(OUT / "sbom.spdx.json")], check=True)


def _checksums() -> None:
    targets = [OUT / name for name in DETERMINISTIC_RESULT_FILES]
    targets += sorted(FIG.glob("*.png"))
    lines = []
    for path in targets:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT)}")
    (OUT / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    config_path = ROOT / "configs" / "benchmarks" / "reference.yaml"
    config = load_yaml_unique(config_path.read_text(encoding="utf-8"))
    seeds = [int(seed) for seed in config["seeds"]]
    reference_time = int(config["reference_time"])
    if reference_time != REFERENCE_TIME:
        raise ValueError(
            f"reference_time must remain {REFERENCE_TIME} for the checked capability fixtures"
        )
    generated_count = int(config["generated_attack_cases_per_seed"])
    if generated_count <= 0:
        raise ValueError("generated_attack_cases_per_seed must be positive")
    architectures = tuple(str(item) for item in config["architectures"])
    if architectures != ARCHITECTURES:
        raise ValueError(f"reference architectures must be {ARCHITECTURES}")
    runs = [
        run_one(seed, architecture, generated_count=generated_count)
        for seed in seeds
        for architecture in architectures
    ]
    summary = summarize_runs(runs)
    hardening = run_self_hardening()
    negative_results = run_negative_results()
    runtime, signed_manifest, manifest = build_guardian("mission", hardened=True)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "runs.json").write_text(json.dumps(runs, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    (OUT / "reference_summary.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "benchmark": "guardian-agent-runtime-reference-v3",
                "benchmark_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "dependency_lock_sha256": hashlib.sha256((ROOT / "requirements.lock").read_bytes()).hexdigest(),
                "runtime_manifest_hash": signed_manifest.manifest_hash,
                "source_package_sha256": manifest["source_package_sha256"],
                "research_source_sha256": _research_source_sha256(),
                "build_identifier": manifest["build_identifier"],
                "seeds": seeds,
                "fixed_attack_cases": len(attack_scenarios()),
                "generated_attack_cases_per_seed": generated_count,
                "benign_cases": len(benign_scenarios()),
                "architectures": list(architectures),
                "reference_time": reference_time,
                "latency": "Host-dependent latency is measured separately with `make latency` and excluded from deterministic reference outputs.",
                "summary": summary,
            },
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    (OUT / "hardening_history.json").write_text(json.dumps(hardening, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUT / "generated_regressions.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "source": "results/hardening_history.json",
                "regression_cases": hardening["regression_cases"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (OUT / "negative_results.json").write_text(json.dumps(negative_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    _write_manifest(manifest, signed_manifest, public_key_b64(runtime.public_key))
    _plot(summary, hardening)
    _generate_supply_chain_outputs()
    _checksums()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
