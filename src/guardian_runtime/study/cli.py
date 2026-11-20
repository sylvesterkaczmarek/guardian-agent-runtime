"""Run the offline pilot and write paired outcomes and independently verifiable samples."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

from guardian_runtime.study.pilot import run_pilot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    parser.add_argument("--timing", action="store_true", help="include host-dependent paired timing")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("choose a new output directory")
    report, samples = run_pilot(timing=args.timing)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Publish a complete directory. Avoid overwriting files on concurrent runs.
    with tempfile.TemporaryDirectory(dir=args.output.parent) as scratch:
        staging = Path(scratch) / "pilot"
        staging.mkdir()
        (staging / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                             encoding="utf-8", newline="\n")
        for family, sample in samples.items():
            out = staging / family
            out.mkdir()
            for name in ("manifest", "bundle"):
                (out / f"{name}.json").write_text(json.dumps(sample[name], indent=2) + "\n", encoding="utf-8")
            (out / "public-key.txt").write_text(sample["public_key"] + "\n", encoding="utf-8")
        staging.rename(args.output)
    for family, summary in report["summary"].items():
        for name in ("guardian", "simple_checker"):
            counts = summary["by_method"][name]
            print(f"{family} {name}: {counts['correctly_resolved_answerable']}/{counts['predicted_answerable']} "
                  f"predicted-answerable claims resolved, {counts['false_confirmations']} false confirmations, "
                  f"{counts['unknown']}/{counts['claims']} unknown", file=sys.stderr)
    print(args.output / "report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
