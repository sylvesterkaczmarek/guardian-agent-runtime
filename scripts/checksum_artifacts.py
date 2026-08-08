from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def main() -> int:
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dist")
    if not directory.exists() or not directory.is_dir():
        raise SystemExit(f"artifact directory does not exist: {directory}")
    output = directory / "checksums.sha256"
    artifacts = sorted(
        path for path in directory.iterdir()
        if path.is_file() and path.name != output.name
    )
    if not artifacts:
        raise SystemExit(f"no release artifacts found in {directory}")
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in artifacts
    ]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
