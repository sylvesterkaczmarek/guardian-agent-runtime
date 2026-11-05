# Guardian Agent Runtime 0.4.0

This release strengthens runtime permission checks, audit ownership and
malformed-result handling. It includes the 0.4 candidate changes and the
independent-review correction for newly active first-match policy rules.

## Independent correction

An existing permit could execute after a newly applicable earlier allow rule
imposed a budget or rate limit that a fresh request would fail. Execution now
checks that the selected allow rule is the same rule that reserved authority.
A changed selection requires fresh authorization. Unrelated rules do not
invalidate a permit, and reserved budgets are not charged twice.

## Verification

Release gates run the complete tests, Ruff, mypy, the bounded Python model,
TLA+, vulnerability auditing, exact reference regeneration and isolated
package verification. The 58 independent cases initially produced four
failures; all must pass after correction. Positive controls remain.
The reference benchmark still uses 26 fixed attacks, 24 seeded attacks per
seed, five seeds and 11 benign tasks. Its denominators are unchanged.

## Distribution status

GitHub release assets are built and verified from the released commit.
PyPI publication and public-install verification are separate workflow jobs.
A GitHub release alone does not imply successful PyPI publication.

## Limits

This is a same-process reference implementation using deterministic local
simulators and benchmark-only keys. It does not establish production
isolation, protected keys, crash durability, restart-safe replay protection,
hardware qualification or safety against unseen attacks. The original
compromised-key secret-read forgery is blocked, while a separate forged
policy-allowed write still demonstrates the signing-key trust limitation.
No paid inference, live agent account or real actuator was used.
