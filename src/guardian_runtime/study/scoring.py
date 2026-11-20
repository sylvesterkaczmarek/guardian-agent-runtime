"""Verify and interpret the observations attached to a composed operation."""
from __future__ import annotations

from collections.abc import Mapping

from guardian_runtime.canonical import canonicalize_request, digest_json
from guardian_runtime.evidence import verify_evidence_bundle
from guardian_runtime.study.workflows import CLAIMS


def unknown() -> dict[str, bool | None]:
    return dict.fromkeys(CLAIMS)


def assess(readings: Mapping, goal: int) -> dict[str, bool | None]:
    verdict = unknown()
    values = readings.get("samples")
    if type(values) is not list or not values or any(type(v) is not int for v in values):
        return verdict
    if readings.get("terminal") is True:
        verdict["completion"] = values[-1] == goal
        verdict["endpoint_in_range"] = 0 <= values[-1] <= 5
    if any(v < 0 or v > 5 for v in values):
        verdict["trajectory_in_range"] = False
    elif readings.get("complete") is True and readings.get("terminal") is True:
        verdict["trajectory_in_range"] = True
    return verdict


def recorded_readings(bundle, root_request, source, *, child_action="apply") -> Mapping | None:
    """Select the observed child from a bundle. Callers verify integrity separately."""
    if bundle["format"] != "guardian-evidence-bundle-v2":
        return None
    expected = digest_json(canonicalize_request(root_request).to_dict())
    roots = [e for e in bundle["events"] if e["parent_permit_id"] is None and e["permit_id"]
             and e["decision"] == "allow" and digest_json(e["normalized_action"]) == expected]
    if len(roots) != 1:
        return None
    children = [
        event for event in bundle["events"]
        if event["parent_permit_id"] == roots[0]["permit_id"] and event["decision"] == "allow"
        and isinstance(event["normalized_action"], Mapping) and event["normalized_action"].get("action") == child_action
    ]
    if len(children) != 1:
        return None
    observation = children[0]["observation"]
    if not observation or observation["source"] != source or not isinstance(observation["readings"], Mapping):
        return None
    return observation["readings"]


def verify_claims(bundle, public_key, manifest_hash, root_request, source, goal, *, child_action="apply"):
    """Authenticate the trace and evaluate the readings linked to the requested operation."""
    valid, reason = verify_evidence_bundle(bundle, public_key, expected_manifest_hash=manifest_hash)
    if not valid:
        raise ValueError(reason)
    readings = recorded_readings(bundle, root_request, source, child_action=child_action)
    return unknown() if readings is None else assess(readings, goal)


def simple_checker(readings: Mapping | None, goal: int) -> dict[str, bool | None]:
    """Interpret the recorded sensor data without verifying signatures."""
    if readings is None:
        return unknown()
    samples = readings.get("samples")
    if type(samples) is not list or not samples or any(type(value) is not int for value in samples):
        return unknown()
    final = samples[-1] if readings.get("terminal") is True else None
    breached = any(not 0 <= sample <= 5 for sample in samples)
    return {
        "completion": None if final is None else final == goal,
        "endpoint_in_range": None if final is None else 0 <= final <= 5,
        "trajectory_in_range": False if breached else (True if final is not None and readings.get("complete") is True else None),
    }
