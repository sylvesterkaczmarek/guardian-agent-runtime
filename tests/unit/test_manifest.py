from dataclasses import replace
from guardian_runtime.crypto import deterministic_private_key
from guardian_runtime.manifest import sign_manifest, verify_manifest


def test_manifest_signature():
    key = deterministic_private_key('manifest-test')
    signed = sign_manifest({'version': 1, 'policy': 'abc'}, key)
    assert verify_manifest(signed, key.public_key())
    assert not verify_manifest(replace(signed, manifest={'version': 2}), key.public_key())


def test_runtime_manifest_binds_benchmark_configuration():
    from guardian_runtime.factory import build_guardian

    _, signed, manifest = build_guardian("mission", hardened=True)
    assert manifest["benchmark_configuration"] == "reference-v3"
    assert len(manifest["benchmark_configuration_hash"]) == 64
    assert signed.manifest["benchmark_configuration_hash"] == manifest["benchmark_configuration_hash"]
