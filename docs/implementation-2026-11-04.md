# November implementation audit

## Scope

Base commit: `0a526d019c4a8e75db5f98b8d8b7021a8cc5410d`.
Candidate branch: `fix/runtime-integrity-20261104`.
Candidate version: `0.4.0rc1`, unpublished.

The audit uses local synthetic requests and controlled simulator/tool fixtures.
No real agent account, paid inference, live spacecraft or external actuator is used.
It is an implementation pass. Independent review remains the next gate.

## Reproduced findings

| Finding | Baseline behaviour | Candidate correction |
| --- | --- | --- |
| G01 authority aliases | Mutating capability input, lookup or clone constraints, or policy constraints, changes effective authority | Owned normalized configuration and detached accessors |
| G02 temporal authorization | A permit issued at time 100 executes at 102 after its allow rule expired at 101; later deny/escalate rules are not checked | Expiry clamp plus execution-time policy revalidation |
| G03 audit aliases | Editing a returned event corrupts the internal signed chain; editing manifest input invalidates its signed object | Detached audit and manifest snapshots |
| G04 typed constraints | Boolean values satisfy numeric enum/equality constraints, including nested values and delegation | Recursive JSON type-aware equality |
| G05 tool result contract | None can raise after an allow event without a result digest; malformed/cyclic output can be returned as success | Validated copied ToolResult or an explicit failed audited attempt |
| G06 verifier input | CLI reads the entire supplied file; excessive nesting is inspected after decoding | Bounded file read and lexical depth precheck |
| G07 local check invocation | `make check` fails to import repository experiment modules when it invokes the pytest executable | Consistent `python -m` invocations |

Baseline `python -m pytest`: 285 tests passed. The initial focused regression file
produced 35 failures, recorded before implementation. Further regressions cover
read-only mapping configuration, one-shot rules iterators, policy replacement,
negative constraint controls, verifier limits and demonstration output preservation.
The focused corpus is software validation, not a measured real-world attack rate.

## Benchmark interpretation

The existing reference architecture comparison and seeds are retained. New unit and
integration cases are kept distinct from the earlier benchmark denominator. The
complete reference suite is regenerated against the candidate source and lock.

Execution-time checking blocks the original compromised-key secret-read forgery.
That exact negative result is retained with a false bypass result and a true blocked
result. A new policy-allowed write still succeeds using forged authority outside the
presented capability scope, demonstrating the remaining key-compromise limitation.
Existing hidden tool side effects, initial proxy bypasses and utility tradeoffs remain
explicit negative controls.

Two older output tests now expect invalid-tool-result instead of success for opaque
or cyclic values. They still require an intact signed execution record. This is an
intentional contract correction, described in the migration notes.

## Dependency audit follow-up

The first hosted candidate audit identified 40 known advisories across two existing
locked dependencies: setuptools 83.0.0 and Pillow 12.3.0. The lock now uses patched
setuptools 84.1.0 and Pillow 13.0.0. No vulnerability ignore list or weakened audit
was introduced. The full reference artifacts, package checks and hosted CI are
rerun against the updated lock. The initial failed audit remains in Actions history.

## Figure encoding follow-up

The first Linux reference regeneration matched all numerical and signed JSON
outputs, but PNG compression bytes differed from macOS. Reference figures now keep
the exact Agg RGBA pixels and use explicit Sub filtering and the standard-library
fixed-Huffman encoder instead of platform-specific Pillow compression. Pixel-exact
round-trip tests cover generated images, noncontiguous arrays and an Agg plot.
The existing byte-for-byte checked-artifact gate remains unchanged.

## Executed implementation checks

On macOS with Python 3.14.7, the complete suite passes 345 tests, compared with the
285-test baseline. Ruff passes and mypy checks all 36 runtime modules. The ten
original audit probes, rerun unchanged from a separate directory, meet their
expected outcomes. The eight-case offline showcase passes. The bounded Python
model checks 4,196 reachable states.

Two consecutive complete reference generations produce identical checked artifact
hashes. The existing architecture comparison retains its workload and headline
rates. The changed negative key-compromise result is recorded explicitly.

Installed-distribution and hosted CI results are recorded separately on the exact
PR head. This record does not claim independent verification or publication.

## Verification and limits

Use [candidate verification](verification.md). Results are attached to the exact PR
head rather than inferred from an earlier run. Keep the baseline evidence, failing
reproductions, final logs and package hashes together for independent review.

No claim is made about production isolation, protected keys, crash durability,
restart-safe replay caches, complete policy synthesis, unseen attack distributions
or equivalence between the bounded formal model and Python implementation.

## Reference semantics

Python's frozen dataclasses do not make nested containers immutable. Snapshot
ownership is therefore enforced explicitly. See the Python dataclasses documentation:
https://docs.python.org/3.12/library/dataclasses.html#frozen-instances
