import hashlib
import json
from pathlib import Path

from guardian_runtime.adversarial import generated_attack_scenarios
from scripts.dependency_inventory import canonical_name, dependency_edges, parse_lock


ROOT = Path(__file__).resolve().parents[1]


def test_seeded_attack_generation_is_repeatable():
    assert generated_attack_scenarios(17) == generated_attack_scenarios(17)
    assert generated_attack_scenarios(17) != generated_attack_scenarios(29)


def test_reference_outputs_exclude_host_dependent_latency():
    runs = json.loads((ROOT / "results" / "runs.json").read_text(encoding="utf-8"))
    assert runs
    assert all(result["decision_latency_ms"] is None for run in runs for result in run["attack_results"])
    assert all(result["decision_latency_ms"] is None for run in runs for result in run["benign_results"])


def test_checked_checksums_match_deterministic_artifacts():
    lines = (ROOT / "results" / "checksums.sha256").read_text(encoding="utf-8").splitlines()
    assert lines
    for line in lines:
        digest, relative = line.split("  ", 1)
        path = ROOT / relative
        assert path.exists()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


def test_dependency_inventory_matches_lock():
    inventory = json.loads((ROOT / "results" / "dependency_inventory.json").read_text(encoding="utf-8"))
    lock_digest = hashlib.sha256((ROOT / "requirements.lock").read_bytes()).hexdigest()
    assert inventory["lock_sha256"] == lock_digest
    names = {item["name"] for item in inventory["packages"]}
    assert {"cryptography", "PyYAML", "numpy", "matplotlib", "hypothesis", "mypy", "pytest", "pytest-cov", "ruff"} <= names



def test_reference_dependency_graph_connects_every_transitive_package():
    packages = parse_lock(ROOT / "requirements.lock")
    graph = dependency_edges(packages)
    package_names = {canonical_name(item["name"]) for item in packages}
    inbound = {
        canonical_name(edge["to"])
        for edge in graph
        if edge["from"] != "guardian-agent-runtime"
    }
    transitive = {
        canonical_name(item["name"])
        for item in packages
        if item["scope"] == "transitive"
    }
    assert transitive <= inbound
    assert all(canonical_name(edge["to"]) in package_names for edge in graph)


def test_reference_metrics_are_bounded_probabilities():
    from experiments.run_reference_suite import run_one

    for architecture in ("no_guardian", "static_acl", "guardian_initial", "guardian_hardened"):
        run = run_one(7, architecture, generated_count=4)
        for metric in (
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
        ):
            assert 0.0 <= run[metric] <= 1.0, (architecture, metric, run[metric])

def test_readme_headline_counts_and_rates_match_checked_results():
    summary_payload = json.loads((ROOT / "results" / "reference_summary.json").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{summary_payload['fixed_attack_cases']} fixed adversarial scenarios" in readme
    assert f"{summary_payload['generated_attack_cases_per_seed']} seeded adversarial scenarios per seed" in readme
    assert f"{summary_payload['benign_cases']} benign tasks" in readme

    labels = {
        "no_guardian": "No Guardian",
        "static_acl": "Static ACL",
        "guardian_initial": "Guardian initial",
        "guardian_hardened": "Guardian hardened",
    }
    for architecture, label in labels.items():
        metrics = summary_payload["summary"][architecture]
        attack = metrics["attack_success_rate"]
        critical = metrics["critical_action_success_rate"]
        benign = metrics["benign_task_completion_rate"]
        tamper = metrics["tampering_detection_rate"]
        attack_text = f"{attack['mean']:.3f}" if attack["std"] == 0 else f"{attack['mean']:.3f} ± {attack['std']:.3f}"
        critical_text = f"{critical['mean']:.3f}" if critical["std"] == 0 else f"{critical['mean']:.3f} ± {critical['std']:.3f}"
        # Bold cells in the hardened row are permitted, so check each formatted value independently.
        assert f"| {label} |" in readme
        assert attack_text in readme
        assert critical_text in readme
        assert f"{benign['mean']:.3f}" in readme
        assert f"{tamper['mean']:.3f}" in readme

def test_readme_limiting_and_hardening_results_match_checked_artifacts():
    summary_payload = json.loads((ROOT / "results" / "reference_summary.json").read_text(encoding="utf-8"))
    hardening = json.loads((ROOT / "results" / "hardening_history.json").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    overpriv = summary_payload["summary"]["guardian_hardened"]["capability_overprivilege_rate"]
    assert f"{overpriv['mean']:.3f} ± {overpriv['std']:.3f}" in readme

    history = hardening["history"][0]
    bypass_count = history["attack_successes_before"]
    minimized_count = len(history["minimized_traces"])
    assert f"finds {bypass_count} manifestations" in readme
    assert f"minimizes them into {minimized_count} executable regression classes" in readme

