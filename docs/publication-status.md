# Publication status

## Current release

Guardian Agent Runtime **0.4.1** is published on GitHub and PyPI.
The PyPI distribution is **`guardian-runtime-assurance`**; the repository remains
`sylvesterkaczmarek/guardian-agent-runtime` and the import remains `guardian_runtime`.
The public PyPI files were downloaded and verified on 5 November 2026.

- [PyPI release](https://pypi.org/project/guardian-runtime-assurance/0.4.1/)
- [GitHub release](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/releases/tag/v0.4.1)
- [Completed release verification](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/actions/runs/41950099605)

Release commit: `6452610f6718e7dcabab2ac3fbfa6f194338c7e1`.
All nine release-workflow jobs passed, including trusted PyPI publication and
public installed-package verification. The publisher is scoped to this GitHub
repository, `release.yml` and the `pypi` environment. No API token or password
was added to the repository.

## Verified packages

The full suite passed **413 tests** from source, built distributions and files
downloaded from public PyPI. This retains all 58 independent runtime-review cases
and adds ten distribution-identity checks. The eight-case offline demonstration,
Ruff, mypy across 36 runtime modules, vulnerability audit, bounded Python model
and hosted TLA+ checks passed. All 42 runtime Python/YAML files matched across
the released source, wheel and source distribution. Reference outputs reproduced
exactly, and numerical benchmark metrics remain unchanged from 0.4.0.

The public PyPI wheel and source distribution are byte-identical to the verified
GitHub release files:

```text
4bd8603ee6e6a6b61509db47a1590bbff16c8e64903d425897bae29fdbb9ab2a  guardian_runtime_assurance-0.4.1-py3-none-any.whl
7fc2fcde90d15fc34bf2637541b4afe9d67f2cf3813a9c6484a7c594508d8fe9  guardian_runtime_assurance-0.4.1.tar.gz
```

## Correct namespace

The existing PyPI project `guardian-agent-runtime` is unrelated QIP helper-backed
software. Its version 0.1.0 is not an older release of this repository and should
not be installed to obtain this code. The original 0.4.0 upload failed without
publishing anything. The earlier assumption that this was merely a missing
publisher on an owned project was corrected after authenticated inspection.
Do not rerun the old 0.4.0 PyPI publish job or configure access to that other project.

Version 0.4.1 uses a distinct distribution name. The repository name, Python
import, CLI commands and runtime behaviour are unchanged. Use a fresh virtual
environment when migrating from a locally installed 0.4.0 GitHub wheel so two
distribution records do not claim the same files.

## Preserved release and limits

The original GitHub 0.4.0 tag and assets remain unchanged at commit
`44e2929864a5a80e4cdea796ab6e5d297811ab3a`. Earlier reviews and failure evidence
remain preserved. This is a same-process research implementation with deterministic
simulators and benchmark-only keys, not production-safety certification.
