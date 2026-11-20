from __future__ import annotations

from dataclasses import asdict
import hashlib
import inspect
import os
from importlib import resources
from pathlib import Path
from collections.abc import Callable
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian_runtime.adapters import AdapterSpec, EffectObserver

from guardian_runtime import __version__
from guardian_runtime.capabilities import CapabilityStore, capability_from_dict
from guardian_runtime.crypto import deterministic_private_key, public_key_b64
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
    return _capability_store_from_text(config_path.read_text(encoding="utf-8"))


def _capability_store_from_text(text: str) -> CapabilityStore:
    try:
        data = load_yaml_unique(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid or ambiguous capability YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("capabilities"), list):
        raise ValueError("capability configuration requires a capabilities list")
    if set(data) != {"capabilities"}:
        raise ValueError("capability configuration contains unknown fields")
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

    adapter_type = type(environment)
    artifact = inspect.getsourcefile(adapter_type)
    if not artifact:
        raise ValueError("use build_integration with an explicit adapter build digest")
    adapter = AdapterSpec.from_file(
        f"{adapter_type.__module__}.{adapter_type.__qualname__}", artifact,
        getattr(environment, "composite_actions", ("proxy_call",)),
    )
    selected_policy = Path(policy_path) if policy_path else _resource_path(
        "guardian", "hardened.yaml" if hardened else "initial.yaml"
    )
    selected_capabilities = Path(capability_path) if capability_path else _resource_path("capabilities", "reference.yaml")
    return _build(
        domain, environment, adapter, selected_policy, selected_capabilities,
        deterministic_private_key("guardian-agent-runtime-reference-key"),
        clock or (lambda: reference_time), "reference-fixed" if clock is None else "reference-custom",
        permit_ttl_seconds, nested_mediation, None, reference_time if clock is None else None,
        reference=True,
    )


def build_integration(
    domain: str, *, environment: Any, adapter: AdapterSpec, signing_key: Ed25519PrivateKey,
    clock: Callable[[], int], clock_policy: str, permit_ttl_seconds: int,
    policy_path: str | Path, capability_path: str | Path, observer: EffectObserver | None = None,
) -> tuple[GuardianRuntime, Any, dict[str, Any]]:
    """Construct a runtime using the integrator's trust anchors and adapter declaration."""
    if not isinstance(signing_key, Ed25519PrivateKey) or not callable(clock):
        raise ValueError("integration requires an explicit signing key and clock")
    if not isinstance(clock_policy, str) or not clock_policy.strip():
        raise ValueError("clock policy name is required")
    return _build(
        domain, environment, adapter, Path(policy_path), Path(capability_path),
        signing_key, clock, clock_policy, permit_ttl_seconds, True, observer, None, reference=False,
    )


def _build(
    domain, environment, adapter: AdapterSpec, selected_policy: Path, selected_capabilities: Path,
    signing_key, clock, clock_policy, permit_ttl_seconds, nested_mediation, observer, reference_time, *, reference,
) -> tuple[GuardianRuntime, Any, dict[str, Any]]:
    if type(permit_ttl_seconds) is not int or permit_ttl_seconds <= 0:
        raise ValueError("permit_ttl_seconds must be a positive integer")
    declared = getattr(environment, "composite_actions", None)
    if declared is not None and frozenset(declared) != frozenset(adapter.composite_actions):
        raise ValueError("adapter declaration disagrees with the environment composite actions")
    benchmark_config = _resource_path("benchmarks", "reference.yaml")
    # Bind the manifest to the exact bytes parsed, even if a configuration file
    # is replaced while the runtime is being constructed.
    policy_bytes = selected_policy.read_bytes()
    capability_bytes = selected_capabilities.read_bytes()
    policy = PolicyEngine.from_text(policy_bytes.decode("utf-8"))
    capabilities = _capability_store_from_text(capability_bytes.decode("utf-8"))
    source_hash = _package_source_hash()
    manifest = {
        "guardian_version": __version__,
        "policy_version": policy.version,
        "policy_hash": hashlib.sha256(policy_bytes).hexdigest(),
        "permitted_tools": [domain],
        "tool_versions": {domain: adapter.build_sha256},
        "adapter_contract_version": 1,
        "adapter": asdict(adapter),
        "permit_ttl_seconds": permit_ttl_seconds,
        "signer_public_key": public_key_b64(signing_key.public_key()),
        "clock_policy": clock_policy,
        "reference_time": reference_time,
        "profile": "reference" if reference else "integration",
        "observer_source": observer.source if observer else None,
        "nested_action_mediation": "guardian-recursive" if nested_mediation else "tool-direct",
        "configuration_hash": hashlib.sha256(capability_bytes).hexdigest(),
        "benchmark_configuration": "observed-v4" if reference else None,
        "benchmark_configuration_hash": hashlib.sha256(benchmark_config.read_bytes()).hexdigest() if reference else None,
        "source_package_sha256": source_hash,
        "build_identifier": os.environ.get(
            "GUARDIAN_BUILD_ID", f"source-sha256:{source_hash[:16]}"
        ),
        "attestation": "software-signed-manifest-only",
    }
    signed_manifest = sign_manifest(manifest, signing_key)
    runtime = GuardianRuntime(
        capabilities=capabilities,
        policy=policy,
        environment=environment,
        signing_key=signing_key,
        runtime_manifest_hash=signed_manifest.manifest_hash,
        clock=clock,
        permit_ttl_seconds=permit_ttl_seconds,
        mediate_nested_actions=nested_mediation,
        composite_actions=adapter.composite_actions,
        observer=observer,
    )
    return runtime, signed_manifest, manifest
