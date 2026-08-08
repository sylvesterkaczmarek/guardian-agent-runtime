from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from guardian_runtime.canonical import digest_json
from guardian_runtime.crypto import sign_object, verify_object


@dataclass(frozen=True)
class SignedManifest:
    manifest: Mapping[str, Any]
    manifest_hash: str
    signature: str


def sign_manifest(manifest: Mapping[str, Any], private_key: Ed25519PrivateKey) -> SignedManifest:
    manifest_hash = digest_json(manifest)
    payload = {"manifest": dict(manifest), "manifest_hash": manifest_hash}
    return SignedManifest(manifest=dict(manifest), manifest_hash=manifest_hash, signature=sign_object(private_key, payload))


def verify_manifest(signed: SignedManifest, public_key: Ed25519PublicKey) -> bool:
    try:
        if digest_json(signed.manifest) != signed.manifest_hash:
            return False
        return verify_object(
            public_key,
            {"manifest": dict(signed.manifest), "manifest_hash": signed.manifest_hash},
            signed.signature,
        )
    except (TypeError, ValueError):
        return False
