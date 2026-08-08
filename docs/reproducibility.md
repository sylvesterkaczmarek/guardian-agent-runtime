# Reproducibility

Reference experiments use fixed seeds `7, 17, 29, 41, 53`, deterministic scenario generation, versioned YAML configuration, deterministic reference-only signing keys, and an exact dependency lock for the checked CPython 3.12/3.13 Linux reference environment.

Create an isolated environment and install the reference dependency set:

```bash
python -m venv .venv
source .venv/bin/activate
make install
```

Run validation and regenerate the reference results:

```bash
make check
make reproduce
```

Verify deterministic outputs against the checked hashes:

```bash
make verify-reproduce
```

`make reproduce` regenerates raw JSON results, aggregate statistics, hardening history, generated regression cases, explicit negative results, figures, the signed runtime manifest, dependency inventory, SPDX SBOM, and SHA-256 checksums. The runtime manifest hashes the selected policy, capability configuration, and packaged Guardian source. The reference summary also hashes the research source that defines implementation, experiments, formal artifacts, and generation scripts. A release pipeline may set `GUARDIAN_BUILD_ID` to an external commit or build identifier.

`make install`, Docker, and CI install `requirements.lock` with dependency resolution disabled, install the project with dependency resolution disabled, and run `pip check`. The lock is therefore treated as the complete checked package set rather than as a partial hint to the resolver. The generated dependency inventory records project-to-direct and package-to-transitive relationships for the reference environment, and the SPDX SBOM is built from the same exact package set and graph. CI additionally runs dependency review and a vulnerability audit.

Security outcomes and checked artifacts are deterministic under the pinned reference environment. Host-dependent timing is deliberately separated from these outputs. Run:

```bash
make latency
```

Latency measurements are written under `results/local/`, include environment metadata, report both decision-path and end-to-end request timing, and are ignored by Git.

The package includes its reference YAML configuration as wheel package data. CI builds a wheel, installs it into an isolated target directory, and runs a Guardian smoke action from outside the source tree.

Reference signing keys are deterministic only for reproducibility. They are public research material and must never be reused in a production security deployment.
