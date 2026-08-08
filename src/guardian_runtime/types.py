from __future__ import annotations

from dataclasses import asdict, dataclass, field
from collections.abc import Mapping
from typing import Any


@dataclass(frozen=True)
class ActionRequest:
    subject: str
    session_id: str
    tool: str
    action: str
    resource: str = ""
    params: Mapping[str, Any] = field(default_factory=dict)
    purpose: str = ""
    capability_id: str = ""
    nonce: str = ""
    observed_state_version: int | None = None
    context: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeState:
    version: int
    values: Mapping[str, Any]


@dataclass(frozen=True)
class ExecutionPermit:
    request_hash: str
    policy_version: str
    capability_id: str
    subject: str
    session_id: str
    issued_at: int
    expires_at: int
    sequence: int
    state_version: int
    rule_id: str | None
    runtime_manifest_hash: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("signature", None)
        return data


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule_id: str | None = None
    permit: ExecutionPermit | None = None
    normalized_request: ActionRequest | None = None


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    status: str
    output: Mapping[str, Any] = field(default_factory=dict)
    state_version: int | None = None


@dataclass(frozen=True)
class EvidenceEvent:
    sequence: int
    timestamp: int
    session_id: str
    subject: str
    requested_action: Mapping[str, Any]
    normalized_action: Mapping[str, Any] | None
    decision: str
    decision_reason: str
    rule_id: str | None
    policy_version: str
    capability_id: str
    runtime_manifest_hash: str
    result_digest: str
    previous_hash: str
    event_hash: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("signature", None)
        return data
