# Candidate verification

## Source checkout

Use Python 3.12 or newer in a fresh virtual environment, then:

```bash
make install
make check
make reproduce
make verify-reproduce
python scripts/showcase.py --output ./guardian-showcase
```

The reference lock is installed with dependency resolution disabled. The showcase
requires a new or empty directory and preserves prior evidence. Both simulators,
all proposed actions and the signing keys are deliberately local research fixtures.

## Installed distribution

```bash
make package
python -c 'from setuptools.build_meta import build_sdist; build_sdist("dist")'
python scripts/verify_distribution.py dist/*.whl dist/*.tar.gz --report installed-check.json
```

The verifier compares packaged runtime bytes, creates a fresh non-editable environment,
installs the exact locked dependencies, checks dependency consistency and package
identity, and runs the full suite from the extracted source distribution outside the
working checkout. It also runs the bounded model, showcase and evidence CLI verifier.

## Review gates

Review the changes against the recorded base commit, reproduce G01-G07, and test
positive cases as well as malformed inputs and failures. Inspect policy timing,
constraint types, ownership, reservation accounting, nested mediation, failed tool
execution, evidence authenticity limits and the changed key-compromise experiment.

Check hosted CI against the final head. The Linux matrix covers Python 3.12-3.14;
macOS checks run on Python 3.14. Do not claim local execution of other environments
or Windows qualification from these jobs. The dependency audit remains a required
job. The formal checks are bounded model results, not a proof of the implementation.

Prompt 1 prepares a draft pull request only. Merge, final version, release and public
installation verification remain Prompt 2 decisions. No release schedule is created.
