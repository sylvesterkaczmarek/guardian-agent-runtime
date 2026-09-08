from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from collections.abc import Iterable, Mapping
from typing import Any
from threading import RLock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from guardian_runtime.canonical import canonical_json, digest_json
from guardian_runtime.crypto import sign_object, verify_object
from guardian_runtime.types import ActionRequest, Decision, EvidenceEvent, ToolResult


GENESIS_HASH = "0" * 64
CHECKPOINT_VERSION = "1"
MAX_EVIDENCE_DEPTH = 64
_HASH = re.compile(r"[0-9a-f]{64}\Z")


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


def _type_name(value: Any) -> str:
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


def _safe_mapping_key(key: Any) -> dict[str, Any]:
    """Return a deterministic, JSON-safe description of an invalid mapping key."""

    import math

    if key is None or isinstance(key, (bool, int, str)):
        return {"type": _type_name(key), "value": _safe_value(key)}
    if isinstance(key, float):
        if math.isfinite(key):
            return {"type": _type_name(key), "value": _safe_value(key)}
        return {"type": _type_name(key), "invalid_float": repr(key)}
    if isinstance(key, bytes):
        return {"type": _type_name(key), "hex": key.hex()}
    return {"type": _type_name(key), "unsupported": True}


def _safe_value(value: Any, *, _ancestors: set[int] | None = None, _depth: int = 0) -> Any:
    """Describe malformed values without losing the entire signed audit event.

    Normal JSON values retain their existing representation. Cycles and excessive
    nesting are explicitly marked; this snapshot is diagnostic evidence, not a
    reconstruction of unsupported Python objects.
    """

    import math

    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return {"invalid_unicode": ascii(value)}
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            str(value)
        except ValueError:
            return {"invalid_integer_hex": hex(value)}
        return value
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return {"invalid_float": repr(value)}
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, bytearray):
        return {"bytearray_hex": bytes(value).hex()}
    if isinstance(value, memoryview):
        return {"memoryview_hex": value.tobytes().hex()}
    if not isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return {"invalid_type": _type_name(value)}
    ancestors = set() if _ancestors is None else _ancestors
    if id(value) in ancestors:
        return {"invalid_cycle": _type_name(value)}
    if _depth >= MAX_EVIDENCE_DEPTH:
        return {"truncated_value": {"reason": "maximum nesting depth", "type": _type_name(value)}}
    ancestors.add(id(value))

    def snapshot(item: Any) -> Any:
        return _safe_value(item, _ancestors=ancestors, _depth=_depth + 1)

    try:
        if isinstance(value, Mapping):
            try:
                mapping_items = list(value.items())
            except Exception as exc:
                return {
                    "invalid_mapping": {
                        "type": _type_name(value),
                        "access_error": _type_name(exc),
                    }
                }
            if all(isinstance(key, str) and key and isinstance(_safe_value(key), str) for key, _ in mapping_items):
                return {key: snapshot(item) for key, item in mapping_items}
            entries = [
                {"key": _safe_mapping_key(key), "value": snapshot(item)}
                for key, item in mapping_items
            ]
            entries.sort(key=lambda entry: canonical_json(entry["key"]))
            return {"invalid_mapping": entries}
        if isinstance(value, (list, tuple)):
            return [snapshot(item) for item in value]
        items = [snapshot(item) for item in value]
        items.sort(key=canonical_json)
        return {"unordered_values": items, "type": _type_name(value)}
    finally:
        ancestors.remove(id(value))


def _request_snapshot(request: ActionRequest) -> dict[str, Any]:
    """Capture the original request without dataclasses.asdict deep-copying untrusted values."""

    return {
        "subject": _safe_value(request.subject),
        "session_id": _safe_value(request.session_id),
        "tool": _safe_value(request.tool),
        "action": _safe_value(request.action),
        "resource": _safe_value(request.resource),
        "params": _safe_value(request.params),
        "purpose": _safe_value(request.purpose),
        "capability_id": _safe_value(request.capability_id),
        "nonce": _safe_value(request.nonce),
        "observed_state_version": _safe_value(request.observed_state_version),
        "context": _safe_value(request.context),
    }


def _result_snapshot(result: ToolResult) -> dict[str, Any]:
    return {
        "ok": _safe_value(result.ok),
        "status": _safe_value(result.status),
        "output": _safe_value(result.output),
        "state_version": _safe_value(result.state_version),
    }


def _safe_identifier(value: Any) -> str:
    if isinstance(value, str):
        return value if isinstance(_safe_value(value), str) else f"<invalid-unicode:{ascii(value)}>"
    return f"<invalid:{_type_name(value)}>"


class EvidenceLog:
    def __init__(self, private_key: Ed25519PrivateKey, runtime_manifest_hash: str) -> None:
        self._private_key = private_key
        self._manifest_hash = runtime_manifest_hash
        self._events: list[EvidenceEvent] = []
        self._lock = RLock()

    @property
    def events(self) -> tuple[EvidenceEvent, ...]:
        with self._lock:
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
        with self._lock:
            sequence = len(self._events) + 1
            previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
            normalized = decision.normalized_request.to_dict() if decision.normalized_request else None
            result_digest = digest_json(_result_snapshot(result)) if result is not None else ""
            payload = {
                "sequence": sequence,
                "timestamp": timestamp,
                "session_id": _safe_identifier(request.session_id),
                "subject": _safe_identifier(request.subject),
                "requested_action": _request_snapshot(request),
                "normalized_action": normalized,
                "decision": "allow" if decision.allowed else "deny",
                "decision_reason": decision.reason,
                "rule_id": decision.rule_id,
                "policy_version": policy_version,
                "capability_id": _safe_identifier(request.capability_id),
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

        return [asdict(event) for event in self.events]

    def checkpoint(self, *, policy_version: str) -> EvidenceCheckpoint:
        return self._checkpoint_for(self.events, policy_version=policy_version)

    def _checkpoint_for(self, events: tuple[EvidenceEvent, ...], *, policy_version: str) -> EvidenceCheckpoint:
        payload = {
            "checkpoint_version": CHECKPOINT_VERSION,
            "event_count": len(events),
            "terminal_hash": events[-1].event_hash if events else GENESIS_HASH,
            "policy_version": policy_version,
            "runtime_manifest_hash": self._manifest_hash,
        }
        return EvidenceCheckpoint(**payload, signature=sign_object(self._private_key, payload))

    def export_bundle(self, *, policy_version: str) -> dict[str, Any]:
        # Both parts describe one snapshot even if execution appends concurrently.
        events = self.events
        return {
            "format": "guardian-evidence-bundle-v1",
            "events": [asdict(event) for event in events],
            "checkpoint": asdict(self._checkpoint_for(events, policy_version=policy_version)),
        }


def _event_schema_error(event: EvidenceEvent) -> str | None:
    if type(event.sequence) is not int or event.sequence < 1:
        return "sequence must be a positive integer"
    if type(event.timestamp) is not int:
        return "timestamp must be an integer"
    for field in ("session_id", "subject", "decision_reason", "policy_version", "capability_id", "signature"):
        if not isinstance(getattr(event, field), str):
            return f"{field} must be a string"
    if event.decision not in ("allow", "deny"):
        return "decision must be allow or deny"
    if event.rule_id is not None and not isinstance(event.rule_id, str):
        return "rule_id must be a string or null"
    if not isinstance(event.requested_action, Mapping):
        return "requested_action must be an object"
    if event.normalized_action is not None and not isinstance(event.normalized_action, Mapping):
        return "normalized_action must be an object or null"
    for field in ("event_hash", "previous_hash", "runtime_manifest_hash", "result_digest"):
        value = getattr(event, field)
        if field == "result_digest" and value == "":
            continue
        if not isinstance(value, str) or _HASH.fullmatch(value) is None:
            return f"{field} must be a SHA-256 hex digest"
    return None


def _checkpoint_schema_error(checkpoint: EvidenceCheckpoint) -> str | None:
    if type(checkpoint.event_count) is not int or checkpoint.event_count < 0:
        return "event_count must be a non-negative integer"
    for field in ("policy_version", "signature"):
        if not isinstance(getattr(checkpoint, field), str):
            return f"{field} must be a string"
    for field in ("terminal_hash", "runtime_manifest_hash"):
        value = getattr(checkpoint, field)
        if not isinstance(value, str) or _HASH.fullmatch(value) is None:
            return f"{field} must be a SHA-256 hex digest"
    return None


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
        schema_error = _event_schema_error(event)
        if schema_error is not None:
            return False, f"malformed evidence event at sequence {expected_sequence}: {schema_error}"
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

        try:
            unsigned = event.unsigned_dict()
            signature = event.signature
            event_hash = unsigned.pop("event_hash")
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
    if not isinstance(bundle, Mapping):
        return False, "evidence bundle must be an object"
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
    schema_error = _checkpoint_schema_error(checkpoint)
    if schema_error is not None:
        return False, f"malformed evidence checkpoint: {schema_error}"
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
