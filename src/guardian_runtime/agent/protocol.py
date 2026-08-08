from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from guardian_runtime.types import ActionRequest


class Agent(Protocol):
    def propose_action(self, observation: Mapping[str, Any], context: Mapping[str, Any]) -> ActionRequest: ...


class CallableAgentAdapter:
    """Optional adapter for any externally supplied agent function.

    The core benchmark does not instantiate this adapter and requires no network or proprietary model.
    """

    def __init__(self, propose: Callable[[Mapping[str, Any], Mapping[str, Any]], ActionRequest]) -> None:
        self._propose = propose

    def propose_action(self, observation: Mapping[str, Any], context: Mapping[str, Any]) -> ActionRequest:
        return self._propose(observation, context)
