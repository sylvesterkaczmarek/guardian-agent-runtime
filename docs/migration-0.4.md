# Migration to the 0.4 series

## Stable formats

ActionRequest, ExecutionPermit and the signed evidence-bundle format are unchanged.
Version 0.4.0 remains available through its original GitHub release.
The PyPI distribution from 0.4.1 is `guardian-runtime-assurance`.
The `guardian-agent-runtime` name on PyPI is unrelated software; it is not an
older release of this repository. The import `guardian_runtime` and both verifier
commands are unchanged. Use a fresh virtual environment when switching from a
locally installed 0.4.0 wheel so two distribution records cannot own the same files.
See [publication status](publication-status.md) and [0.4.1 notes](release-0.4.1.md).

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

## Changed first-match policy rules

A permit becomes invalid when a different allow rule becomes the first applicable
rule before execution. Obtain fresh authorization with a new nonce. This includes
explicit rules replacing default-allow decisions. The old reservation is not
refunded, and valid reservations are not charged twice.
