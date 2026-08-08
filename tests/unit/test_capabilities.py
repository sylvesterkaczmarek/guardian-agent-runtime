import pytest

from guardian_runtime.capabilities import (
    Capability,
    CapabilityError,
    CapabilityStore,
    capability_from_dict,
    capability_is_subset,
)
from guardian_runtime.factory import load_capability_store
from guardian_runtime.types import ActionRequest


def req(cap, action="actuator_set", params=None, nonce="n1", resource="", purpose="operations"):
    return ActionRequest("agent-1", "s", "sandbox", action, resource, params or {}, purpose, cap, nonce)


def test_expired_capability_is_rejected():
    store = load_capability_store()
    ok, reason = store.validate(req("cap-expired", params={"value": 1}), 2_000_000_000)
    assert not ok and "expired" in reason


def test_nonce_replay_is_rejected():
    store = load_capability_store()
    r = req("cap-actuator", params={"value": 1})
    assert store.validate(r, 2_000_000_000)[0]
    assert not store.validate(r, 2_000_000_000)[0]


def test_delegation_cannot_expand_authority():
    store = load_capability_store()
    child = Capability(
        "child",
        "agent-1",
        "sandbox",
        "*",
        "*",
        max_invocations=50,
        delegation_depth=1,
        parent_id="cap-parent",
        expires_at=2_000_001_000,
    )
    with pytest.raises(CapabilityError):
        store.add(child)


def test_valid_child_is_subset():
    parent = Capability(
        "p",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/*",
        max_invocations=10,
        delegation_depth=2,
        expires_at=100,
    )
    child = Capability(
        "c",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/input.txt",
        max_invocations=5,
        delegation_depth=1,
        parent_id="p",
        expires_at=90,
    )
    assert capability_is_subset(child, parent)


def test_child_cannot_drop_required_parent_constraint():
    parent = Capability(
        "p",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/*",
        constraints={"format": {"enum": ["text"], "required": True}},
        purpose=("operations",),
        max_invocations=10,
        delegation_depth=2,
        expires_at=100,
    )
    child = Capability(
        "c",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/input.txt",
        constraints={},
        purpose=("operations",),
        max_invocations=5,
        delegation_depth=1,
        parent_id="p",
        expires_at=90,
    )
    assert not capability_is_subset(child, parent)


def test_child_cannot_drop_parent_purpose_restriction():
    parent = Capability(
        "p",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/*",
        purpose=("operations",),
        max_invocations=10,
        delegation_depth=2,
        expires_at=100,
    )
    child = Capability(
        "c",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/input.txt",
        purpose=(),
        max_invocations=5,
        delegation_depth=1,
        parent_id="p",
        expires_at=90,
    )
    assert not capability_is_subset(child, parent)


def _delegated_store(parent_limit=2):
    parent = Capability(
        "parent",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/*",
        constraints={"format": {"enum": ["text"], "required": True}},
        purpose=("operations",),
        max_invocations=parent_limit,
        delegation_depth=2,
        expires_at=100,
    )
    child_a = Capability(
        "child-a",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/a.txt",
        constraints={"format": {"enum": ["text"], "required": True}},
        purpose=("operations",),
        max_invocations=parent_limit,
        delegation_depth=1,
        parent_id="parent",
        expires_at=90,
    )
    child_b = Capability(
        "child-b",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/b.txt",
        constraints={"format": {"enum": ["text"], "required": True}},
        purpose=("operations",),
        max_invocations=parent_limit,
        delegation_depth=1,
        parent_id="parent",
        expires_at=90,
    )
    return CapabilityStore([parent, child_a, child_b])


def _child_request(cap, resource, nonce):
    return ActionRequest(
        subject="agent-1",
        session_id="s",
        tool="sandbox",
        action="read_file",
        resource=resource,
        params={"format": "text"},
        purpose="operations",
        capability_id=cap,
        nonce=nonce,
    )


def test_parent_revocation_invalidates_delegated_child():
    store = _delegated_store()
    store.revoke("parent")
    ok, reason = store.validate(_child_request("child-a", "/tmp/a.txt", "n1"), 10)
    assert not ok
    assert "ancestor revoked" in reason


def test_sibling_children_share_parent_invocation_budget():
    store = _delegated_store(parent_limit=2)
    assert store.validate(_child_request("child-a", "/tmp/a.txt", "n1"), 10)[0]
    assert store.validate(_child_request("child-a", "/tmp/a.txt", "n2"), 10)[0]
    ok, reason = store.validate(_child_request("child-b", "/tmp/b.txt", "n3"), 10)
    assert not ok
    assert "ancestor invocation limit" in reason
    assert store.invocation_count("parent") == 2


def test_parent_nonce_replay_protection_applies_across_siblings():
    store = _delegated_store(parent_limit=4)
    assert store.validate(_child_request("child-a", "/tmp/a.txt", "shared"), 10)[0]
    ok, reason = store.validate(_child_request("child-b", "/tmp/b.txt", "shared"), 10)
    assert not ok
    assert "replayed nonce" in reason


def test_capability_parser_rejects_string_purpose():
    with pytest.raises(CapabilityError, match="purpose must be a sequence"):
        capability_from_dict(
            {
                "capability_id": "bad-purpose",
                "subject": "agent-1",
                "tool": "sandbox",
                "action": "read_file",
                "purpose": "operations",
            }
        )


def test_capability_config_rejects_duplicate_yaml_keys(tmp_path):
    path = tmp_path / "duplicate-capabilities.yaml"
    path.write_text(
        "capabilities:\n"
        "  - capability_id: duplicate\n"
        "    subject: agent-1\n"
        "    tool: sandbox\n"
        "    action: read_file\n"
        "    action: write_file\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="ambiguous capability YAML"):
        load_capability_store(path)


def test_structured_enum_delegation_is_checked_without_crashing():
    parent = Capability(
        "structured-parent",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/*",
        constraints={"selector": {"enum": [{"kind": "text"}, {"kind": "json"}]}},
        max_invocations=4,
        delegation_depth=2,
        expires_at=100,
    )
    child = Capability(
        "structured-child",
        "agent-1",
        "sandbox",
        "read_file",
        "/tmp/input.txt",
        constraints={"selector": {"enum": [{"kind": "text"}]}},
        max_invocations=2,
        delegation_depth=1,
        parent_id="structured-parent",
        expires_at=90,
    )
    assert capability_is_subset(child, parent)
