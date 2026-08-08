from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

from dependency_inventory import dependency_edges, parse_lock


def _spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name).replace(".", "-")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "results" / "sbom.spdx.json"
    locked = parse_lock(root / "requirements.lock")
    graph = dependency_edges(locked)
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    project_version = str(project["version"])
    project_id = _spdx_id("guardian-agent-runtime")
    packages = [
        {
            "SPDXID": project_id,
            "name": "guardian-agent-runtime",
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    ids = {"guardian-agent-runtime": project_id}
    for item in locked:
        spdx_id = _spdx_id(item["name"])
        ids[item["name"]] = spdx_id
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": item["name"],
                "versionInfo": item["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "primaryPackagePurpose": "LIBRARY",
                "comment": f"Reference environment scope: {item['scope']}",
            }
        )

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": project_id,
        }
    ]
    for edge in graph:
        source = ids[edge["from"]]
        target = ids[edge["to"]]
        if edge["scope"] == "development-direct":
            relationships.append(
                {
                    "spdxElementId": target,
                    "relationshipType": "DEV_DEPENDENCY_OF",
                    "relatedSpdxElement": source,
                }
            )
        elif edge["scope"] == "build-direct":
            relationships.append(
                {
                    "spdxElementId": target,
                    "relationshipType": "BUILD_DEPENDENCY_OF",
                    "relatedSpdxElement": source,
                }
            )
        else:
            relationships.append(
                {
                    "spdxElementId": source,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target,
                }
            )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "guardian-agent-runtime-reference-sbom",
        "documentNamespace": (
            "https://github.com/sylvesterkaczmarek/guardian-agent-runtime/"
            f"sbom/{project_version}/reference-v3"
        ),
        "creationInfo": {
            "creators": ["Person: Sylvester Kaczmarek"],
            "created": "2026-08-08T00:00:00Z",
        },
        "packages": packages,
        "relationships": relationships,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
