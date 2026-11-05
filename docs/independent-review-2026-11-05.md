# Independent release review

Original candidate: 2ceecc2d427df591238b073340bb3f74e7a300af.
Date: 5 November 2026.

A fresh macOS checkout and pinned environment reproduced all 345 candidate
tests. A separately authored 58-case suite produced 54 passes and four
failures before any runtime repair. The failures affect both default-allow
and explicit fallback policies when a newly active earlier allow rule adds
a resource budget or rate limit. Fresh authorization rejects these requests
but the candidate's old permit incorrectly executes them.

The repair requires the currently selected first matching allow rule to
equal the originally authorized rule. A changed selection rejects the
permit before execution without consuming an additional reservation.
Unrelated rules, boundary-valid permits and decimal budgets remain positive
controls. The original failing reproductions are retained in artifacts.
The regression suite is tests/regression/test_independent_release_review.py.

After the Mac remote-execution quota was exhausted, verification continued
on isolated GitHub-hosted runners. The preparation run requires all 58
independent checks, the complete 403-test suite, lint, type checks, bounded
model, two identical reference generations and installed-wheel tests before
it creates a staging commit. The pull request and release pipelines repeat
full verification on the exact committed source. Hosted results, artifact
hashes and publication status are separate inspectable records.

This review is independent of the implementation test design, but is not
external third-party security certification. Scope remains the documented
same-process simulator and trusted-tool model. Key compromise, concealed
tool effects, restart durability and production isolation remain explicit
limits. Publication requires the complete release gates to pass.
