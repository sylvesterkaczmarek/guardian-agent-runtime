from __future__ import annotations

import hashlib
import os
from importlib import resources
from pathlib import Path
from collections.abc import Callable
from typing import Any

import yaml

from guardian_runtime import __version__
from guardian_runtime.capabilities import CapabilityStore, capability_from_dict
from guardian_runtime.crypto import deterministic_private_key
from guardian_runtime.guardian import GuardianRuntime
from guardian_runtime.manifest import sign_manifest
from guardian_runtime.policy import PolicyEngine
from guardian_runtime.simulator import MissionEnvironment, SandboxEnvironment
from guardian_runtime.yamlutil import load_yaml_unique


_SOURCE_ROOT = Path(__file__).resolve().parents[2]
ROOT = _SOURCE_ROOT if (_SOURCE_ROOT / "pyproject.toml").exists() else Path.cwd()
REFERENCE_TIME = 2_000_000_000



def _package_source_hash() -> str:
    package_root = Path(__file__).resolve().parent
    hasher = hashlib.sha256()
    files = sorted(
        path
        for path in package_root.rglob("*")
        if path.is_file() and path.suffix in {".py", ".yaml"}
    )
    for path in files:
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        data = path.read_bytes()
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return hasher.hexdigest()

def _resource_path(group: str, name: str) -> Path:
    return Path(str(resources.files("guardian_runtime.resources").joinpath(group, name)))


def reference_config_path(group: str, name: str) -> Path:
    return _resource_path(group, name)


def load_capability_store(path: str | Path | None = None) -> CapabilityStore:
    config_path = Path(path) if path else _resource_path("capabilities", "reference.yaml")
    try:
        data = load_yaml_unique(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid or ambiguous capability YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("capabilities"), list):
        raise ValueError("capability configuration requires a capabilities list")
    return CapabilityStore(capability_from_dict(item) for item in data["capabilities"])


def build_guardian(
    domain: str,
    *,
    hardened: bool = False,
    reference_time: int = REFERENCE_TIME,
    clock: Callable[[], int] | None = None,
    permit_ttl_seconds: int = 5,
    policy_path: str | Path | None = None,
    capability_path: str | Path | None = None,
    environment_override: Any | None = None,
    nested_mediation: bool | None = None,
) -> tuple[GuardianRuntime, Any, dict[str, Any]]:
    if nested_mediation is None:
        nested_mediation = hardened

    if environment_override is not None:
        environment = environment_override
    elif domain == "mission":
        environment = MissionEnvironment()
    elif domain == "sandbox":
        environment = SandboxEnvironment()
    else:
        raise ValueError(f"unknown domain: {domain}")

    selected_policy = Path(policy_path) if policy_path else _resource_path(
        "guardian", "hardened.yaml" if hardened else "initial.yaml"
    )
    selected_capabilities = Path(capability_path) if capability_path else _resource_path("capabilities", "reference.yaml")
    benchmark_config = _resource_path("benchmarks", "reference.yaml")
    policy = PolicyEngine.from_file(selected_policy)
    signing_key = deterministic_private_key("guardian-agent-runtime-reference-key")
    source_hash = _package_source_hash()
    manifest = {
        "guardian_version": __version__,
        "policy_version": policy.version,
        "policy_hash": hashlib.sha256(selected_policy.read_bytes()).hexdigest(),
        "permitted_tools": [domain],
        "tool_versions": {domain: "sim-3"},
        "nested_action_mediation": "guardian-recursive" if nested_mediation else "tool-direct",
        "configuration_hash": hashlib.sha256(selected_capabilities.read_bytes()).hexdigest(),
        "benchmark_configuration": "reference-v3",
        "benchmark_configuration_hash": hashlib.sha256(benchmark_config.read_bytes()).hexdigest(),
        "source_package_sha256": source_hash,
        "build_identifier": os.environ.get(
            "GUARDIAN_BUILD_ID", f"source-sha256:{source_hash[:16]}"
        ),
        "attestation": "software-signed-manifest-only",
    }
    signed_manifest = sign_manifest(manifest, signing_key)
    runtime = GuardianRuntime(
        capabilities=load_capability_store(selected_capabilities),
        policy=policy,
        environment=environment,
        signing_key=signing_key,
        runtime_manifest_hash=signed_manifest.manifest_hash,
        clock=clock or (lambda: reference_time),
        permit_ttl_seconds=permit_ttl_seconds,
        mediate_nested_actions=nested_mediation,
    )
    return runtime, signed_manifest, manifest
