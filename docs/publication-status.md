# Publication status

## Correct distribution

This repository's PyPI distribution is `guardian-runtime-assurance`.
The GitHub repository remains `sylvesterkaczmarek/guardian-agent-runtime` and
the Python import remains `guardian_runtime`. The existing PyPI distribution
`guardian-agent-runtime` is unrelated QIP helper-backed software, not an older
release of this repository. Its version 0.1.0 must not be used for this project.

The initial 0.4.0 upload failed with `invalid-publisher`. Authenticated inspection
on 5 November 2026 confirmed that the existing PyPI project is not owned by this
repository's maintainer; the earlier missing-publisher diagnosis was incomplete.
No upload succeeded and no changes were made to that other project.

## Version 0.4.1 publication

A pending publisher is configured under the maintainer's account for the distinct
distribution name. The release workflow creates that project on first successful
publication and then verifies its public package hashes and isolated installation.
Until those jobs succeed, this document records preparation rather than a claim
that the version is already available on PyPI. The completed workflow and PyPI
release page are the authoritative publication records.

| Field | Value |
| --- | --- |
| PyPI distribution | guardian-runtime-assurance |
| GitHub owner | sylvesterkaczmarek |
| Repository | guardian-agent-runtime |
| Workflow filename | release.yml |
| Environment | pypi |

No API token or password is stored in this repository. The workflow uses PyPI
trusted publishing. No further attempt should target the unrelated old name.

## Preserved earlier release

GitHub version 0.4.0 remains at commit
44e2929864a5a80e4cdea796ab6e5d297811ab3a with its original tags, assets and hashes.
The original review, 403 tests and published-GitHub download verification remain
valid for that software. Version 0.4.1 is a distribution-identity correction;
it does not replace or rewrite those existing assets.

The runtime remains a same-process research implementation using deterministic
simulators and benchmark-only keys, not a production-safety certification.
