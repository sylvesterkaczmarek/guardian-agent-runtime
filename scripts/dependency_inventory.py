from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


RUNTIME_DIRECT = {canonical_name(name) for name in {"cryptography", "PyYAML", "numpy", "matplotlib"}}
DEV_DIRECT = {canonical_name(name) for name in {"hypothesis", "mypy", "pytest", "pytest-cov", "ruff"}}
BUILD_DIRECT = {canonical_name(name) for name in {"setuptools", "wheel"}}

# Dependency edges for the checked Python 3.12/3.13 reference environment. These
# edges are deliberately stored alongside the flat exact-version lock so the SBOM can
# represent the dependency graph rather than pretending every transitive package is a
# direct project dependency. Optional extras and dependencies that apply only to older
# Python versions are excluded from this reference graph.
REFERENCE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "cryptography": ("cffi",),
    "cffi": ("pycparser",),
    "matplotlib": (
        "contourpy",
        "cycler",
        "fonttools",
        "kiwisolver",
        "numpy",
        "packaging",
        "pillow",
        "pyparsing",
        "python-dateutil",
    ),
    "contourpy": ("numpy",),
    "python-dateutil": ("six",),
    "hypothesis": ("attrs", "sortedcontainers"),
    "mypy": ("mypy_extensions", "pathspec", "typing_extensions"),
    "pytest": ("iniconfig", "packaging", "pluggy", "Pygments"),
    "pytest-cov": ("coverage", "pytest", "pluggy"),
    "wheel": ("packaging",),
}


def parse_lock(path: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    canonical_seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN.fullmatch(line)
        if not match:
            raise ValueError(f"requirements.lock contains an unsupported entry: {line}")
        name, version = match.groups()
        canonical = canonical_name(name)
        if canonical in canonical_seen:
            raise ValueError(f"requirements.lock contains duplicate package: {name}")
        canonical_seen.add(canonical)
        scope = "transitive"
        if canonical in RUNTIME_DIRECT:
            scope = "runtime-direct"
        elif canonical in DEV_DIRECT:
            scope = "development-direct"
        elif canonical in BUILD_DIRECT:
            scope = "build-direct"
        packages.append({"name": name, "version": version, "scope": scope})
    return packages


def dependency_edges(packages: list[dict[str, str]]) -> list[dict[str, str]]:
    by_canonical = {canonical_name(item["name"]): item["name"] for item in packages}
    edges: list[dict[str, str]] = []

    # Project-to-direct dependency relationships retain environment scope explicitly.
    for item in packages:
        if item["scope"] != "transitive":
            edges.append(
                {
                    "from": "guardian-agent-runtime",
                    "to": item["name"],
                    "scope": item["scope"],
                }
            )

    for parent_raw, children_raw in REFERENCE_DEPENDENCIES.items():
        parent = canonical_name(parent_raw)
        if parent not in by_canonical:
            raise ValueError(f"dependency graph parent missing from lock: {parent_raw}")
        for child_raw in children_raw:
            child = canonical_name(child_raw)
            if child not in by_canonical:
                raise ValueError(
                    f"dependency graph child missing from lock: {parent_raw} -> {child_raw}"
                )
            edges.append(
                {
                    "from": by_canonical[parent],
                    "to": by_canonical[child],
                    "scope": "package-dependency",
                }
            )

    inbound = {canonical_name(edge["to"]) for edge in edges if edge["from"] != "guardian-agent-runtime"}
    orphaned_transitive = sorted(
        item["name"]
        for item in packages
        if item["scope"] == "transitive" and canonical_name(item["name"]) not in inbound
    )
    if orphaned_transitive:
        raise ValueError(
            "reference dependency graph leaves transitive packages unconnected: "
            + ", ".join(orphaned_transitive)
        )
    return edges


def inventory(lock_path: Path) -> dict:
    packages = parse_lock(lock_path)
    return {
        "schema_version": 2,
        "lock_file": str(lock_path.name),
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "python_reference": "CPython 3.12/3.13 on Linux",
        "packages": packages,
        "dependency_graph": dependency_edges(packages),
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "results" / "dependency_inventory.json"
    payload = inventory(root / "requirements.lock")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
