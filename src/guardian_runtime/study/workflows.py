"""Trusted adapters for the two discrete, local study workflows."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from guardian_runtime.adapters import AdapterSpec, EffectObserver
from guardian_runtime.crypto import deterministic_private_key
from guardian_runtime.factory import REFERENCE_TIME, build_integration, reference_config_path
from guardian_runtime.study import file_backend
from guardian_runtime.types import ActionRequest, RuntimeState, ToolResult

MODES = ("normal", "acknowledged_noop", "committed_error", "excursion", "wrong_final", "missing", "delayed")
CLAIMS = ("completion", "endpoint_in_range", "trajectory_in_range")
FAMILIES = {"joint": ("submit_motion", "parent-motion", 3), "file": ("commit_batch", "parent-file", 4)}


def run_joint_workflow(mode: str, target: int) -> tuple[bool, list[int], list[int]]:
    # The encoder samples the joint state after every discrete transition.
    setpoints = {
        "normal": (2, target), "acknowledged_noop": (), "committed_error": (target,),
        "excursion": (7, target), "wrong_final": (7,), "missing": (2, target), "delayed": (2, target),
    }
    position = 0
    encoder = [position]
    for command in setpoints[mode]:
        position += command - position
        encoder.append(position)
    visible = [] if mode == "missing" else encoder[:-1] if mode == "delayed" else encoder.copy()
    return mode != "committed_error", encoder, visible


class StudyEnvironment:
    def __init__(self, family: str, mode: str, *, ready: bool = True, view: str = "trajectory"):
        if view not in ("acknowledgement", "terminal", "trajectory"):
            raise ValueError("unknown observer view")
        self.view = view
        if family not in FAMILIES or mode not in MODES:
            raise ValueError("unknown study family or mode")
        self.family = family
        self.mode = mode
        self.ready = ready
        self.composite_actions = (FAMILIES[family][0],)
        self.commits = [0]
        self.visible: list[int] = []
        self.invocations = 0

    def snapshot(self) -> RuntimeState:
        return RuntimeState(self.invocations, {"ready": self.ready})

    def check_invariants(self, request: ActionRequest) -> tuple[bool, str]:
        target = request.params.get("target")
        allowed = self.ready and type(target) is int and 0 <= target <= 5
        if self.family == "file" and target not in (3, 4):
            allowed = False
        return allowed, "target and initial state checked"

    def build_nested_requests(self, request: ActionRequest) -> tuple[ActionRequest, ...]:
        return tuple(replace(request, action=a, capability_id=a, nonce=f"{request.nonce}-{a}") for a in ("prepare", "apply"))

    def execute(self, request: ActionRequest) -> ToolResult:
        if request.action == "prepare":
            return ToolResult(True, "prepared", state_version=self.invocations)
        if request.action != "apply":
            raise ValueError("unknown primitive operation")
        run = file_backend.run_file_workflow if self.family == "file" else run_joint_workflow
        ok, self.commits, self.visible = run(self.mode, request.params["target"])
        self.invocations += 1
        return ToolResult(ok, "acknowledged" if ok else "reported-error", state_version=self.invocations)

    def read_observer(self, request: ActionRequest, result: ToolResult) -> dict:
        # Only this read interface is visible to the verifier. The scorer keeps commits.
        if request.action != "apply":
            return {}
        if self.view == "acknowledgement":
            return {}
        fresh = self.mode not in ("missing", "delayed")
        samples = self.visible if self.view == "trajectory" else self.visible[-1:]
        return {"samples": samples.copy(), "terminal": fresh, "complete": fresh and self.view == "trajectory"}

    def runtime(self):
        sources = [Path(__file__).read_bytes()]
        if self.family == "file":
            sources.append(Path(file_backend.__file__).read_bytes())
        digest = sha256(b"".join(sha256(source).digest() for source in sources)).hexdigest()
        return build_integration(
            "study", environment=self, adapter=AdapterSpec(self.family, digest, self.composite_actions),
            signing_key=deterministic_private_key("offline-observation-pilot-only"),
            clock=lambda: REFERENCE_TIME, clock_policy="frozen-offline-study", permit_ttl_seconds=5,
            policy_path=reference_config_path("study", "policy.yaml"),
            capability_path=reference_config_path("study", "capabilities.yaml"),
            observer=EffectObserver(self.family + "-" + self.view, self.read_observer),
        )


def proposal(family: str, target: int | None = None) -> ActionRequest:
    action, cap, goal = FAMILIES[family]
    return ActionRequest("study-agent", "offline-trial", "study", action, params={"target": goal if target is None else target},
                         purpose="study", capability_id=cap, nonce="trial")
