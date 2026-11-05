"""Run a bounded, offline demonstration using synthetic actions and benchmark keys."""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile

from guardian_runtime.crypto import public_key_b64
from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.factory import REFERENCE_TIME, build_guardian
from guardian_runtime.simulator import SandboxEnvironment
from guardian_runtime.tools import PermitError
from guardian_runtime.types import ActionRequest


def request(**changes):
    return replace(
        ActionRequest(
            "agent-1",
            "showcase",
            "sandbox",
            "write_file",
            resource="/tmp/showcase.txt",
            params={"content": "synthetic evidence"},
            purpose="operations",
            capability_id="cap-write-tmp",
            nonce="demo",
        ),
        **changes,
    )


def run_showcase():
    rows = []
    monitor, _, _ = build_guardian("sandbox", hardened=True)
    decision, result = monitor.execute_request(request())
    rows.append(
        {
            "case": "scoped_write",
            "expected": "EXECUTED",
            "observed": "EXECUTED" if decision.allowed and result and result.ok else "REJECTED",
        }
    )
    bundle = monitor.evidence.export_bundle(policy_version=monitor.policy.version)
    verified, _ = verify_evidence_bundle(bundle, monitor.public_key)
    rows.append({"case": "signed_evidence", "expected": "VERIFIED", "observed": "VERIFIED" if verified else "INVALID"})
    decision, _ = monitor.execute_request(request(resource="/private/not-authorized", nonce="outside"))
    rows.append(
        {"case": "outside_scope", "expected": "DENIED", "observed": "DENIED" if not decision.allowed else "ALLOWED"}
    )
    for case in ("permit_replay", "revoked_permit"):
        guarded, _, _ = build_guardian("sandbox", hardened=True)
        approved = guarded.evaluate(request())
        assert approved.permit is not None and approved.normalized_request is not None
        if case == "permit_replay":
            guarded.gateway.execute(approved.normalized_request, approved.permit)
        else:
            guarded.capabilities.revoke(approved.permit.capability_id)
        try:
            guarded.gateway.execute(approved.normalized_request, approved.permit)
            observed = "EXECUTED"
        except PermitError:
            observed = "BLOCKED"
        rows.append({"case": case, "expected": "BLOCKED", "observed": observed})
    with tempfile.TemporaryDirectory(prefix="guardian-showcase-policy-") as directory:
        policy = Path(directory) / "policy.yaml"
        policy.write_text(
            f"version: showcase\ndefault: deny\nrules:\n  - id: lease\n    effect: allow\n    expires_at: {REFERENCE_TIME + 1}\n",
            encoding="utf-8",
        )
        clock = [REFERENCE_TIME]
        guarded, _, _ = build_guardian("sandbox", hardened=True, policy_path=policy, clock=lambda: clock[0])
        approved = guarded.evaluate(request())
        assert approved.permit is not None and approved.normalized_request is not None
        clock[0] += 1
        try:
            guarded.gateway.execute(approved.normalized_request, approved.permit)
            observed = "EXECUTED"
        except PermitError:
            observed = "BLOCKED"
        rows.append({"case": "expired_policy", "expected": "BLOCKED", "observed": observed})
    tampered = deepcopy(bundle)
    tampered["events"][0]["decision"] = "deny"
    accepted, _ = verify_evidence_bundle(tampered, monitor.public_key)
    rows.append(
        {"case": "modified_evidence", "expected": "REJECTED", "observed": "VERIFIED" if accepted else "REJECTED"}
    )

    class InvalidOutput(SandboxEnvironment):
        def execute(self, proposed):
            self.state.version += 1
            return None

    guarded, _, _ = build_guardian("sandbox", hardened=True, environment_override=InvalidOutput())
    _, result = guarded.execute_request(request())
    invalid_audited = bool(
        result and not result.ok and result.status == "invalid-tool-result" and len(guarded.evidence.events) == 1
    )
    rows.append(
        {
            "case": "malformed_tool_output",
            "expected": "FAILED_AND_AUDITED",
            "observed": "FAILED_AND_AUDITED" if invalid_audited else "INCORRECT",
        }
    )
    for row in rows:
        row["passed"] = row["expected"] == row["observed"]
    return (
        {
            "schema_version": 1,
            "evidence_type": "SYNTHETIC_SOFTWARE_CHECKS_ONLY",
            "cases": rows,
            "passed": sum(row["passed"] for row in rows),
            "total": len(rows),
        },
        bundle,
        public_key_b64(monitor.public_key),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New or empty directory for synthetic reports")
    args = parser.parse_args()
    if args.output and args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
        parser.error("output directory must be absent or empty; existing evidence is preserved")
    report, bundle, public_key = run_showcase()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        for name, value in (("showcase.json", report), ("evidence.json", bundle)):
            (args.output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (args.output / "public-key.txt").write_text(public_key + "\n", encoding="utf-8")
    for row in report["cases"]:
        print(f"{row['case']:<26} {row['observed']}")
    print(f"Synthetic checks: {report['passed']}/{report['total']}")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
