import json
import sys
from unittest.mock import patch

import pytest

from guardian_runtime.jsonutil import MAX_JSON_BYTES, loads_unique, read_json_file
from guardian_runtime.verifier import cli, manifest_cli


def test_json_depth_is_rejected_before_decoder_allocation():
    with patch("guardian_runtime.jsonutil.json.loads") as decoder:
        with pytest.raises(ValueError, match="nesting"):
            loads_unique("[" * 129 + "0" + "]" * 129)
        decoder.assert_not_called()


def test_quoted_brackets_and_escaped_quotes_are_not_nesting():
    value = {"string": '"' + "[" * 1000 + "\\" + "]" * 1000}
    assert loads_unique(json.dumps(value)) == value


def test_bounded_file_read_accepts_boundary_and_rejects_extra_byte(tmp_path):
    path = tmp_path / "json"
    path.write_bytes(b"{}")
    assert read_json_file(path, max_bytes=2) == {}
    path.write_bytes(b"{} ")
    with pytest.raises(ValueError, match="exceeds"):
        read_json_file(path, max_bytes=2)


@pytest.mark.parametrize("module", [cli, manifest_cli])
def test_verifier_cli_rejects_oversized_sparse_input(tmp_path, monkeypatch, module):
    path = tmp_path / "too-large.json"
    with path.open("wb") as handle:
        handle.seek(MAX_JSON_BYTES)
        handle.write(b"0")
    monkeypatch.setattr(sys, "argv", ["verify", str(path), "--public-key", "AAAA"])
    assert module.main() == 2
