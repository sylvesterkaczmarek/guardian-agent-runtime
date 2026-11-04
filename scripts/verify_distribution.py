"""Verify the built wheel against its sdist in an isolated non-editable install."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import venv
import zipfile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    wheel, sdist = args.wheel.resolve(strict=True), args.sdist.resolve(strict=True)
    env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
    env["PYTHONNOUSERSITE"] = "1"
    with tempfile.TemporaryDirectory(prefix="guardian-installed-check-") as directory:
        root = Path(directory)
        extracted = root / "source"
        extracted.mkdir()
        with tarfile.open(sdist, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > 10000 or sum(item.size for item in members) > 100 * 1024 * 1024:
                raise ValueError("distribution exceeds verification limits")
            archive.extractall(extracted, filter="data")
        roots = list(extracted.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("sdist must contain exactly one project directory")
        project = roots[0]
        version = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        package = project / "src" / "guardian_runtime"
        with zipfile.ZipFile(wheel) as archive:
            source_files = {
                "guardian_runtime/" + path.relative_to(package).as_posix(): path.read_bytes()
                for path in package.rglob("*")
                if path.is_file() and path.suffix in {".py", ".yaml"}
            }
            wheel_files = {
                name: archive.read(name)
                for name in archive.namelist()
                if name.startswith("guardian_runtime/") and Path(name).suffix in {".py", ".yaml"}
            }
            if source_files != wheel_files:
                raise ValueError("wheel runtime bytes differ from source distribution")
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

        def run(arguments):
            subprocess.run([str(python), *arguments], cwd=project, env=env, check=True, timeout=300)

        run(["-m", "pip", "install", "--disable-pip-version-check", "--no-deps", "-r", "requirements.lock"])
        run(["-m", "pip", "install", "--no-index", "--no-deps", str(wheel)])
        run(["-m", "pip", "check"])
        run(
            [
                "-c",
                "import guardian_runtime,pathlib,sys; p=pathlib.Path(guardian_runtime.__file__).resolve(); assert pathlib.Path(sys.prefix).resolve() in p.parents; assert guardian_runtime.__version__ == sys.argv[1]; print('Installed runtime:',p)",
                version,
            ]
        )
        run(["-m", "pytest"])
        run(["formal/check_model.py"])
        run(["scripts/showcase.py", "--output", str(root / "showcase")])
        proof = root / "showcase"
        public_key = (proof / "public-key.txt").read_text(encoding="utf-8").strip()
        run(["-m", "guardian_runtime.verifier.cli", str(proof / "evidence.json"), "--public-key", public_key])
        payload = {
            "version": version,
            "status": "PASS",
            "runtime_files_matched": len(source_files),
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "sdist_sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(),
            "installation": "isolated, non-editable, outside checkout",
        }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
