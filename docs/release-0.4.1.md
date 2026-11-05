# Guardian Agent Runtime 0.4.1

## Package identity

This repository publishes on PyPI as `guardian-runtime-assurance`. The existing
`guardian-agent-runtime` PyPI project is unrelated QIP helper-backed software;
its version 0.1.0 was incorrectly treated as this repository's prior release.
No upload to that project succeeded and no changes were made to it.

The GitHub repository, `guardian_runtime` import, verifier command names and
runtime behaviour remain unchanged. Version 0.4.1 preserves the original
0.4.0 GitHub tag and artifacts while making the distribution identity explicit.

## Verification

The release gates retain the complete test suite, including all 58 independent
review checks, vulnerability auditing, Ruff, mypy, bounded model checking,
TLA+, exact benchmark regeneration, isolated package installation and the
eight-case offline demonstration. Additional tests reject mismatched or
ambiguous distribution names and versions. The installed verifier checks both
Python module version and the distribution metadata obtained from Python's
package registry. Public PyPI files must match the verified build hashes.

The dependency inventory and SBOM identify the actual distribution using the
project metadata. Project URLs point to the source repository and issue tracker.
The 26 fixed attacks, 24 seeded attacks per seed, five seeds and 11 benign tasks
are unchanged. Updated signed artifacts bind the new version and source hash.

## Installation

After the public publication job succeeds:

```bash
python -m pip install guardian-runtime-assurance==0.4.1
```

Use a fresh virtual environment. Do not install the unrelated
`guardian-agent-runtime` distribution. Consult `docs/publication-status.md` for
the recorded status; a GitHub release alone does not establish PyPI availability.

## Limits

This is a same-process reference implementation with deterministic simulators
and benchmark-only keys. It does not establish production isolation, protected
key storage, crash/restart durability, hardware qualification or safety against
unseen attacks. Signing-key compromise and hidden side effects retain explicit
negative controls. No paid inference or real actuator is used by this release.
