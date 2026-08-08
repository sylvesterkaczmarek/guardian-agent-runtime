from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from guardian_runtime.canonical import canonical_json


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    """Create a deterministic benchmark-only signing key.

    Production deployments must use independently generated protected keys.
    """
    seed = hashlib.sha256(label.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign_object(private_key: Ed25519PrivateKey, payload: Any) -> str:
    signature = private_key.sign(canonical_json(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_object(public_key: Ed25519PublicKey, payload: Any, signature: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature, validate=True), canonical_json(payload))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def public_key_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes_raw()
    return base64.b64encode(raw).decode("ascii")


def load_public_key_b64(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ValueError("invalid Base64 Ed25519 public key") from exc
