# What this repository does not claim

The benchmark does not prove that a reference monitor can make arbitrary advanced agents safe.

The environments are small deterministic simulators. The Guardian and tools run in one process, so the experiment does not establish resistance to a compromised operating system, memory corruption in the monitor, side channels, covert channels, or hardware attacks. The signed runtime manifest is software evidence, not hardware attestation.

Replay caches, consumed nonces, revocation state, invocation budgets, policy rate-limit state, and resource budgets are process-local in this reference implementation. A deployment that preserves signing authority across restarts must persist monotonic security state or invalidate the prior permit/session epoch on restart. The benchmark does not claim restart-safe replay protection.

The hardened Guardian blocks the included fixed and seeded attack distribution. This does not establish completeness against unknown attack classes.

The defensive loop is bounded and review-gated. It minimizes discovered traces, constructs and evaluates a generalized candidate, and requires that candidate to match the reviewed checked policy before retention. It does not synthesize arbitrary verified policies.

A signed evidence bundle establishes integrity relative to the signing key and its signed checkpoint. It detects tail truncation relative to that checkpoint, but a stateless verifier cannot distinguish an older, previously valid signed bundle from the latest bundle. Rollback detection therefore requires external freshness state or a trusted checkpoint anchor. It also cannot establish semantic correctness when a trusted component is wrong. Compromise of the signing key defeats the policy-attestation and evidence trust boundaries.

A lower-level tool can also violate its declared contract. The checked negative experiment deliberately creates a tool that performs an undeclared actuator side effect during an authorized file read. The Guardian cannot constrain behavior that is absent from the tool interface and state model.

The aggressive-policy experiment shows the opposite failure mode. Blanket restrictions can reduce useful task completion even when they reduce available authority.

The initial proxy confused-deputy result remains the principal policy-composition failure. Valid outer proxy authority is insufficient when the lower-level tool can exercise hidden nested authority. The hardened architecture closes the included proxy class by requiring a separately scoped nested capability and recursively mediating the nested action through Guardian. This does not prove that every possible higher-order tool composition or external tool implementation is correctly modeled.
