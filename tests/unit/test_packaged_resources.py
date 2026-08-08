from pathlib import Path

from guardian_runtime.factory import reference_config_path


ROOT = Path(__file__).resolve().parents[2]


def test_packaged_reference_configs_match_source_configs():
    for group, names in {
        "guardian": ("initial.yaml", "hardened.yaml", "overfit.yaml", "aggressive.yaml"),
        "capabilities": ("reference.yaml",),
        "benchmarks": ("reference.yaml",),
    }.items():
        for name in names:
            source = (ROOT / "configs" / group / name).read_bytes()
            packaged = reference_config_path(group, name).read_bytes()
            assert packaged == source, f"packaged config drift: {group}/{name}"
