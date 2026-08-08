from __future__ import annotations

import argparse
from pathlib import Path

from guardian_runtime.crypto import load_public_key_b64
from guardian_runtime.evidence import verify_evidence_bundle, verify_events
from guardian_runtime.jsonutil import loads_unique


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Guardian execution evidence.")
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--public-key", required=True, help="Base64 Ed25519 public key")
    parser.add_argument("--policy-version")
    parser.add_argument("--manifest-hash")
    parser.add_argument(
        "--allow-unanchored-events",
        action="store_true",
        help="Permit legacy raw event arrays. Tail deletion cannot be detected without a signed checkpoint.",
    )
    args = parser.parse_args()

    try:
        payload = loads_unique(args.evidence.read_text(encoding="utf-8"))
        public_key = load_public_key_b64(args.public_key)
    except (OSError, ValueError) as exc:
        print(f"invalid verifier input: {exc}")
        return 2
    if isinstance(payload, dict):
        ok, reason = verify_evidence_bundle(
            payload,
            public_key,
            expected_policy_version=args.policy_version,
            expected_manifest_hash=args.manifest_hash,
        )
    elif isinstance(payload, list) and args.allow_unanchored_events:
        ok, reason = verify_events(
            payload,
            public_key,
            expected_policy_version=args.policy_version,
            expected_manifest_hash=args.manifest_hash,
        )
        if ok:
            reason += "; tail deletion was not assessed because no signed checkpoint was supplied"
    else:
        ok, reason = False, "expected a signed evidence bundle; use --allow-unanchored-events only for legacy raw arrays"
    print(reason)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
