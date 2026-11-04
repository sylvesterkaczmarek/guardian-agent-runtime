# Migration to the 0.4 candidate

## Stable formats

ActionRequest, ExecutionPermit and the signed evidence-bundle format are unchanged.
The candidate is version 0.4.0rc1 and remains unpublished. Independent review and
release approval are separate steps.

## Owned authority

CapabilityStore.add and PolicyEngine construction own normalized copies of their
configuration. CapabilityStore.get, CapabilityStore.clone and PolicyEngine.policy
expose detached snapshots. Editing a previously supplied dictionary or returned
object no longer edits active authority. PolicyEngine.policy is read-only as a
configuration access point. Construct a new runtime with a corresponding reviewed
manifest to change policy; do not replace runtime internals in place.

Boolean values and numbers no longer compare as interchangeable constraint values.
This applies recursively inside arrays/objects, including enum, eq, in, forbid,
not_in, neq and delegated finite sets. Numbers retain numeric equality, so 1 and
1.0 compare equally. Review configurations that previously relied on True == 1.

## Permit lifetime

Permits expire no later than their authorizing allow rule. The runtime gateway also
rechecks current emergency restrictions, deny/escalation rules and the original
allow rule immediately before execution. A newly active restriction can therefore
reject a previously issued permit. Existing authority reservations are conservative
and are not refunded or charged again. Rate limits, action sequences and budgets
remain authorization-time accounting, not execution-time throughput guarantees.

The low-level ToolGateway accepts an optional execution-policy callback. Construct
it through GuardianRuntime for the policy revalidation described here. Standalone
gateway integrations must supply the corresponding trusted callback themselves.

## Output and audit ownership

A tool must return ToolResult with a boolean ok, non-empty UTF-8 status, JSON mapping
output and a non-negative integer or null state_version. Invalid output produces
ok=False and status=invalid-tool-result, while preserving execution accounting and
a signed result digest. This replaces earlier cases that returned success for opaque
or cyclic outputs or raised after tool execution. Failures may have partial effects;
reusing the permit remains forbidden.

EvidenceLog.events and append return detached snapshots. Export methods remain
writable copies. Mutating those copies should invalidate the copy's signature while
leaving the internal log intact. SignedManifest input is copied before signing.
These ownership rules do not authenticate the producer or protect the signing key.

## Verifier limits

Both CLI verifiers reject files over 32 MiB as input errors. JSON nesting is checked
before decoding and limited to 128 levels, as before. Larger evidence collections
need separately bounded bundles and external ordering/freshness management. The
checker does not silently split or truncate evidence.
