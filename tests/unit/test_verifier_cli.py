import json
import sys
from dataclasses import asdict

import pytest

from guardian_runtime.crypto import public_key_b64
from guardian_runtime.factory import build_guardian
from guardian_runtime.verifier import cli, manifest_cli


@pytest.fixture
def verifier_input(tmp_path):
    runtime, signed, _ = build_guardian("mission", hardened=True)
    bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(bundle), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(asdict(signed)), encoding="utf-8")
    return runtime, evidence, manifest


@pytest.mark.parametrize("module,index", [(cli, 1), (manifest_cli, 2)])
def test_verifier_entry_functions_accept_signed_files(verifier_input, monkeypatch, module, index):
    runtime = verifier_input[0]
    monkeypatch.setattr(sys, "argv", ["verify", str(verifier_input[index]), "--public-key", public_key_b64(runtime.public_key)])
    assert module.main() == 0


@pytest.mark.parametrize("content", [
    "[" * 10000 + "0" + "]" * 10000,
    '{"value":NaN}', '{"value":1e9999}',
    '{"a":1,"a":2}',
    b"\xff",
])
@pytest.mark.parametrize("module", [cli, manifest_cli])
def test_malformed_json_and_encoding_produce_input_error(tmp_path, monkeypatch, module, content):
    path = tmp_path / "invalid.json"
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    monkeypatch.setattr(sys, "argv", ["verify", str(path), "--public-key", "AAAA"])
    assert module.main() == 2


@pytest.mark.parametrize("module", [cli, manifest_cli])
def test_untrusted_error_text_cannot_write_terminal_controls(tmp_path, monkeypatch, capsys, module):
    path = tmp_path / "invalid.json"
    path.write_text('{"\\u001b[2J":1,"\\u001b[2J":2}', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["verify", str(path), "--public-key", "AAAA"])
    assert module.main() == 2
    assert "\x1b" not in capsys.readouterr().out


def test_raw_events_require_explicit_unanchored_opt_in(verifier_input, monkeypatch, capsys):
    runtime, evidence, _ = verifier_input
    evidence.write_text("[]", encoding="utf-8")
    arguments = ["verify", str(evidence), "--public-key", public_key_b64(runtime.public_key)]
    monkeypatch.setattr(sys, "argv", arguments)
    assert cli.main() == 1
    monkeypatch.setattr(sys, "argv", [*arguments, "--allow-unanchored-events"])
    assert cli.main() == 0
    assert "tail deletion was not assessed" in capsys.readouterr().out


def test_manifest_hash_is_not_coerced_to_a_string(verifier_input, monkeypatch):
    runtime, _, manifest = verifier_input
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["manifest_hash"] = 1
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["verify", str(manifest), "--public-key", public_key_b64(runtime.public_key)])
    assert manifest_cli.main() == 2


def test_a_key_embedded_in_a_manifest_does_not_replace_the_trusted_key(verifier_input, monkeypatch):
    from guardian_runtime.crypto import deterministic_private_key

    runtime, _, manifest = verifier_input
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["public_key"] = public_key_b64(runtime.public_key)
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    wrong_key = deterministic_private_key("different-trust-anchor").public_key()
    monkeypatch.setattr(sys, "argv", ["verify", str(manifest), "--public-key", public_key_b64(wrong_key)])
    assert manifest_cli.main() == 1
