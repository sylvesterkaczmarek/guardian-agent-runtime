"""Version 1 of the trusted tool-adapter and observer contract."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from guardian_runtime.types import ActionRequest, ToolResult


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    build_sha256: str
    composite_actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("adapter name is required")
        if not isinstance(self.build_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", self.build_sha256):
            raise ValueError("adapter build requires a SHA-256 digest")
        actions = self.composite_actions
        if type(actions) is not tuple or not all(isinstance(a, str) and re.fullmatch(r"[a-z][a-z0-9_]*", a) for a in actions):
            raise ValueError("composite actions must be a tuple of canonical action names")
        if len(set(actions)) != len(actions):
            raise ValueError("duplicate composite actions")

    @classmethod
    def from_file(cls, name: str, artifact: str | Path, composite_actions: tuple[str, ...] = ()) -> AdapterSpec:
        return cls(name, hashlib.sha256(Path(artifact).read_bytes()).hexdigest(), composite_actions)


@dataclass(frozen=True)
class EffectObserver:
    source: str
    read: Callable[[ActionRequest, ToolResult], Mapping[str, Any]]

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip() or not callable(self.read):
            raise ValueError("observer requires a source identity and a read function")
