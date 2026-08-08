from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from collections.abc import Iterable, Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from guardian_runtime.canonical import canonical_json, digest_json
from guardian_runtime.crypto import sign_object, verify_object
from guardian_runtime.types import ActionRequest, Decision, EvidenceEvent, ToolResult


GENESIS_HASH = "0" * 64
CHECKPOINT_VERSION = "1"


class EvidenceVerificationError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceCheckpoint:
    checkpoint_version: str
    event_count: int
    terminal_hash: str
    policy_version: str
    runtime_manifest_hash: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("signature", None)
        return data


def _safe_value(value: Any) -> Any:
    import math

    if isinstance(value, float) and not math.isfinite(value):
        return {"invalid_float": repr(value)}
    if isinstance(value, dict):
        if all(isinstance(key, str) and key for key in value):
            return {key: _safe_value(item) for key, item in value.items()}
        items = sorted(value.items(), key=lambda pair: repr(pair[0]))
        return {
            "invalid_mapping": [
                {"key_repr": repr(key), "value": _safe_value(item)}
                for key, item in items
            ]
        }
    if isinstance(value, (list, tuple)):
        return [_safe_value(v) for v in value]
    return value


class EvidenceLog:
    def __init__(self, private_key: Ed25519PrivateKey, runtime_manifest_hash: str) -> None:
        self._private_key = private_key
        self._manifest_hash = runtime_manifest_hash
        self._events: list[EvidenceEvent] = []

    @property
    def events(self) -> tuple[EvidenceEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        *,
        timestamp: int,
        request: ActionRequest,
        decision: Decision,
        policy_version: str,
        result: ToolResult | None,
    ) -> EvidenceEvent:
        sequence = len(self._events) + 1
        previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        normalized = decision.normalized_request.to_dict() if decision.normalized_request else None
        result_digest = digest_json(asdict(result)) if result is not None else ""
        payload = {
            "sequence": sequence,
            "timestamp": timestamp,
            "session_id": request.session_id,
            "subject": request.subject,
            "requested_action": _safe_value(request.to_dict()),
            "normalized_action": normalized,
            "decision": "allow" if decision.allowed else "deny",
            "decision_reason": decision.reason,
            "rule_id": decision.rule_id,
            "policy_version": policy_version,
            "capability_id": request.capability_id,
            "runtime_manifest_hash": self._manifest_hash,
            "result_digest": result_digest,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
        signed_payload = {**payload, "event_hash": event_hash}
        signature = sign_object(self._private_key, signed_payload)
        event = EvidenceEvent(**signed_payload, signature=signature)
        self._events.append(event)
        return event

    def export(self) -> list[dict[str, Any]]:
        """Export raw events.

        Raw event chains detect modification, insertion, reordering and interior deletion,
        but a signed checkpoint is required to detect tail truncation. Prefer export_bundle().
        """

        return [asdict(event) for event in self._events]

    def checkpoint(self, *, policy_version: str) -> EvidenceCheckpoint:
        payload = {
            "checkpoint_version": CHECKPOINT_VERSION,
            "event_count": len(self._events),
            "terminal_hash": self._events[-1].event_hash if self._events else GENESIS_HASH,
            "policy_version": policy_version,
            "runtime_manifest_hash": self._manifest_hash,
        }
        return EvidenceCheckpoint(**payload, signature=sign_object(self._private_key, payload))

    def export_bundle(self, *, policy_version: str) -> dict[str, Any]:
        return {
            "format": "guardian-evidence-bundle-v1",
            "events": self.export(),
            "checkpoint": asdict(self.checkpoint(policy_version=policy_version)),
        }


def verify_events(
    events: Iterable[EvidenceEvent | Mapping[str, Any]],
    public_key: Ed25519PublicKey,
    *,
    expected_policy_version: str | None = None,
    expected_manifest_hash: str | None = None,
) -> tuple[bool, str]:
    previous_hash = GENESIS_HASH
    seen_hashes: set[str] = set()
    expected_sequence = 1
    for raw in events:
        try:
            event = raw if isinstance(raw, EvidenceEvent) else EvidenceEvent(**dict(raw))
        except (TypeError, ValueError) as exc:
            return False, f"malformed evidence event at sequence {expected_sequence}: {exc}"
        if event.sequence != expected_sequence:
            return False, f"sequence mismatch at {expected_sequence}"
        if event.previous_hash != previous_hash:
            return False, f"broken hash chain at sequence {event.sequence}"
        if event.event_hash in seen_hashes:
            return False, f"replayed event at sequence {event.sequence}"
        if expected_policy_version is not None and event.policy_version != expected_policy_version:
            return False, f"policy version mismatch at sequence {event.sequence}"
        if expected_manifest_hash is not None and event.runtime_manifest_hash != expected_manifest_hash:
            return False, f"runtime manifest mismatch at sequence {event.sequence}"

        unsigned = event.unsigned_dict()
        signature = event.signature
        event_hash = unsigned.pop("event_hash")
        try:
            recomputed = hashlib.sha256(canonical_json(unsigned)).hexdigest()
        except Exception as exc:
            return False, f"non-canonical evidence at sequence {event.sequence}: {exc}"
        if recomputed != event_hash:
            return False, f"event hash mismatch at sequence {event.sequence}"
        signed_payload = {**unsigned, "event_hash": event_hash}
        if not verify_object(public_key, signed_payload, signature):
            return False, f"signature verification failed at sequence {event.sequence}"
        previous_hash = event.event_hash
        seen_hashes.add(event.event_hash)
        expected_sequence += 1
    return True, "evidence chain valid"


def verify_evidence_bundle(
    bundle: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    *,
    expected_policy_version: str | None = None,
    expected_manifest_hash: str | None = None,
) -> tuple[bool, str]:
    if bundle.get("format") != "guardian-evidence-bundle-v1":
        return False, "unsupported evidence bundle format"
    raw_events = bundle.get("events")
    raw_checkpoint = bundle.get("checkpoint")
    if not isinstance(raw_events, list) or not isinstance(raw_checkpoint, Mapping):
        return False, "evidence bundle requires events and checkpoint"

    try:
        checkpoint = EvidenceCheckpoint(**dict(raw_checkpoint))
    except (TypeError, ValueError) as exc:
        return False, f"malformed evidence checkpoint: {exc}"
    if checkpoint.checkpoint_version != CHECKPOINT_VERSION:
        return False, "unsupported evidence checkpoint version"
    if not verify_object(public_key, checkpoint.unsigned_dict(), checkpoint.signature):
        return False, "evidence checkpoint signature verification failed"
    if expected_policy_version is not None and checkpoint.policy_version != expected_policy_version:
        return False, "evidence checkpoint policy version mismatch"
    if expected_manifest_hash is not None and checkpoint.runtime_manifest_hash != expected_manifest_hash:
        return False, "evidence checkpoint runtime manifest mismatch"

    ok, reason = verify_events(
        raw_events,
        public_key,
        expected_policy_version=checkpoint.policy_version,
        expected_manifest_hash=checkpoint.runtime_manifest_hash,
    )
    if not ok:
        return False, reason

    terminal_hash = GENESIS_HASH
    if raw_events:
        last = raw_events[-1]
        if not isinstance(last, Mapping) or not isinstance(last.get("event_hash"), str):
            return False, "malformed terminal evidence event"
        terminal_hash = str(last["event_hash"])
    if checkpoint.event_count != len(raw_events):
        return False, "evidence event count does not match signed checkpoint"
    if checkpoint.terminal_hash != terminal_hash:
        return False, "evidence terminal hash does not match signed checkpoint"
    return True, "evidence bundle valid"
