# Changelog

## 0.4.0rc1

Unpublished review candidate prepared in November 2026.

### Authority and execution

- Own capability and policy snapshots, including nested constraints and collections.
- Return detached capability, policy and audit records rather than writable internal aliases.
- Preserve JSON boolean types in scalar, enum, exclusion and delegation comparisons.
- Bound permits by their authorizing rule's expiry and recheck current restrictions before execution.
- Retain one-way nonce, invocation, rate and resource reservations without charging twice.
- Validate and copy tool results; malformed outputs produce a failed audited result with a burned permit.
- Detach nested manifest input before signing.

### Verification

- Bound verifier file reads and reject excess JSON nesting before decoder allocation.
- Repair the Makefile's interpreter selection so local checks match CI's module invocation.
- Add synthetic regressions, an eight-case offline demonstration and isolated wheel/sdist verification.
- Add macOS checks alongside the Linux Python-version matrix.
- Regenerate reference artifacts and record the changed compromised-key experiment without hiding remaining trust limits.

No merge, tag, GitHub release or package-index publication is performed by this candidate.
