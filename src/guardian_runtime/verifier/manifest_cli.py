from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path

from guardian_runtime.crypto import load_public_key_b64
from guardian_runtime.manifest import SignedManifest, verify_manifest
from guardian_runtime.jsonutil import loads_unique
from guardian_runtime.verifier._output import print_result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Guardian signed runtime manifest.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--public-key",
        required=True,
        help="Trusted Base64 Ed25519 public key. Do not trust a key supplied only by the manifest file.",
    )
    args = parser.parse_args()

    try:
        payload = loads_unique(args.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print_result(f"invalid manifest file: {exc}")
        return 2
    if not isinstance(payload, Mapping):
        print_result("invalid manifest file: expected a JSON object")
        return 2
    try:
        signed = SignedManifest(
            manifest=payload["manifest"],
            manifest_hash=payload["manifest_hash"],
            signature=payload["signature"],
        )
        public_key = load_public_key_b64(args.public_key)
    except (KeyError, TypeError, ValueError) as exc:
        print_result(f"invalid manifest input: {exc}")
        return 2
    if not isinstance(signed.manifest_hash, str) or not isinstance(signed.signature, str):
        print_result("invalid manifest input: manifest_hash and signature must be strings")
        return 2
    if not isinstance(signed.manifest, Mapping):
        print_result("invalid manifest input: manifest must be an object")
        return 2

    if verify_manifest(signed, public_key):
        print_result("runtime manifest valid")
        return 0
    print_result("runtime manifest verification failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
