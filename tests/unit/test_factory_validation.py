import hashlib

import pytest

from guardian_runtime.factory import build_guardian, load_capability_store, reference_config_path
from guardian_runtime.policy import PolicyEngine


@pytest.mark.parametrize("field", ["revoked", "expiry", "capabilites"])
def test_capability_configuration_rejects_unrecognised_fields(tmp_path, field):
    configuration = tmp_path / "capabilities.yaml"
    configuration.write_text(f"capabilities: []\n{field}: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown fields"):
        load_capability_store(configuration)


def test_manifest_hashes_the_configuration_bytes_actually_loaded(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    capability_path = tmp_path / "capabilities.yaml"
    policy_bytes = reference_config_path("guardian", "hardened.yaml").read_bytes()
    capability_bytes = reference_config_path("capabilities", "reference.yaml").read_bytes()
    policy_path.write_bytes(policy_bytes)
    capability_path.write_bytes(capability_bytes)
    parse_policy = PolicyEngine.from_text

    def replace_files_during_load(cls, text):
        policy = parse_policy(text)
        policy_path.write_text('version: replaced\nrules: []\n', encoding="utf-8")
        capability_path.write_text('capabilities: []\n', encoding="utf-8")
        return policy

    monkeypatch.setattr(PolicyEngine, "from_text", classmethod(replace_files_during_load))
    runtime, _, manifest = build_guardian(
        "mission", hardened=True, policy_path=policy_path, capability_path=capability_path,
    )
    assert runtime.policy.version == "1.2-hardened"
    assert runtime.capabilities.get("cap-observe") is not None
    assert manifest["policy_hash"] == hashlib.sha256(policy_bytes).hexdigest()
    assert manifest["configuration_hash"] == hashlib.sha256(capability_bytes).hexdigest()
