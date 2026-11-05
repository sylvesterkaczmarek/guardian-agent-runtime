# Publication status

## GitHub release

Version 0.4.0 was published on 5 November 2026 from commit
44e2929864a5a80e4cdea796ab6e5d297811ab3a. PR #4 is merged.
The wheel and source distribution passed all 403 tests in an isolated
installation, including the 58 independent release checks. Their public
GitHub asset hashes are checked again by the final public release check.

The release tag and uploaded assets are preserved without replacement.
Two stale candidate-status passages in the packaged documentation are
corrected in the current repository README and migration guide. They do
not change the released runtime code, formats, tests or package hashes.

## PyPI publication

The publish job in Actions run 41943465213 was refused with
invalid-publisher: no corresponding trusted publisher matched the token.
No 0.4.0 upload succeeded in that run; public PyPI installation was skipped.
This is a publisher authorization requirement, not a failed runtime test.

A project owner must configure a GitHub trusted publisher for the existing
guardian-agent-runtime PyPI project with these fields:

| Field | Value |
| --- | --- |
| Owner | sylvesterkaczmarek |
| Repository | guardian-agent-runtime |
| Workflow filename | release.yml |
| Environment | pypi |

After configuration, rerun the failed jobs in run 41943465213. This reuses
the original verified distributions, leaves the GitHub tag/assets alone
and runs the public PyPI hash and isolated-install verification. Do not
rerun the successful build job, which intentionally refuses an existing
version tag. Never place a PyPI password or API token in repository files.

Official guidance is available at
https://docs.pypi.org/trusted-publishers/adding-a-publisher/
and https://docs.pypi.org/trusted-publishers/troubleshooting/.

## Evidence

Independent preparation run: 41942655639.
Final PR verification run: 41943094507.
Release run: 41943465213.
The release assets include distribution.json, COMMIT.txt and SHA256SUMS.txt.
No production-agent, real-actuator or safety-certification claim is made.
