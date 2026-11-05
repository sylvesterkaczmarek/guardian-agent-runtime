"""Package identity must distinguish this project from unrelated PyPI software."""

import json
from pathlib import Path
import tomllib

import pytest

from scripts.verify_distribution import validate_distribution_metadata

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "name", ["guardian-runtime-assurance", "guardian_runtime_assurance", "Guardian.Runtime.Assurance"]
)
def test_valid_normalized_identity(name):
    validate_distribution_metadata(
        f"Name: {name}\nVersion: 0.4.1\n\n".encode(), name="guardian-runtime-assurance", version="0.4.1"
    )


@pytest.mark.parametrize(
    "metadata",
    [
        b"Name: guardian-agent-runtime\nVersion: 0.4.1\n\n",
        b"Name: guardian-runtime-assurance\nVersion: 0.1.0\n\n",
        b"Name: guardian-runtime-assurance\nName: another\nVersion: 0.4.1\n\n",
        b"Name: guardian-runtime-assurance\nVersion: 0.4.1\nVersion: 0.4.1\n\n",
        b"Version: 0.4.1\n\n",
        b"Name: guardian-runtime-assurance\n\n",
    ],
)
def test_wrong_or_ambiguous_identity_is_rejected(metadata):
    with pytest.raises(ValueError):
        validate_distribution_metadata(metadata, name="guardian-runtime-assurance", version="0.4.1")


def test_supply_chain_artifacts_use_project_distribution():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["name"] == "guardian-runtime-assurance"
    inventory = json.loads((ROOT / "results/dependency_inventory.json").read_text())
    direct_edges = [edge for edge in inventory["dependency_graph"] if edge["scope"] != "package-dependency"]
    assert direct_edges and all(edge["from"] == project["name"] for edge in direct_edges)
    sbom = json.loads((ROOT / "results/sbom.spdx.json").read_text())
    assert sbom["packages"][0]["name"] == project["name"]
    assert sbom["packages"][0]["versionInfo"] == project["version"]
