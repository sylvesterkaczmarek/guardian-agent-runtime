# What this repository does not claim

The benchmark does not prove that a reference monitor can make arbitrary advanced agents safe.

The environments are small deterministic simulators. The Guardian and tools run in one process, so the experiment does not establish resistance to a compromised operating system, memory corruption in the monitor, side channels, covert channels, or hardware attacks. The signed runtime manifest is software evidence, not hardware attestation.

Replay caches, consumed nonces, revocation state, invocation budgets, policy rate-limit state, and resource budgets are process-local in this reference implementation. A deployment that preserves signing authority across restarts must persist monotonic security state or invalidate the prior permit/session epoch on restart. The benchmark does not claim restart-safe replay protection.

Authorization is intentionally reservation-based. Once a valid request passes capability, policy, and invariant checks, its nonce and invocation authority are consumed and its policy rate/resource budget is recorded before tool execution. A caller that obtains valid permits and never executes them can therefore reduce availability. Reclaiming abandoned reservations safely would require a durable transaction or lease protocol that this reference implementation does not provide.

Calls through a runtime and its gateway share a reentrant execution lock. This serialises mediated tool execution and prevents concurrent permit reuse within that runtime, at the cost of parallel throughput for slow tools. It does not protect direct simulator-state changes, shared external devices or other processes. Custom tools remain part of the trusted computing base. Failed or interrupted tools can have partial side effects, so their permits are consumed and the attempt is recorded rather than retried automatically.

Resource-budget accounting stores exact `Fraction` totals in `PolicyRuntimeState.resource_usage`. Integrations that export that internal state must explicitly convert those values, preferably to numerator/denominator pairs when exact restoration matters. Normal requests, permits and evidence retain their JSON representation.

Request parameters and context are limited to 64 nesting levels; generic canonical JSON and verifier JSON input permit 128 to accommodate signed envelopes. These limits are explicit across supported Python versions. Deeper requests are rejected before authority is reserved. Diagnostic evidence marks cycles and excessive nesting explicitly. Expired pending request copies are discarded on the next authorization, but consumed nonce, invocation and policy reservations are retained.

The bounded formal models assume atomic execution and evidence append. Their checked invariants apply to those models; they do not establish equivalence to the Python code, durable audit storage or crash-safe execution.

The reference dependency lock fixes package versions and installs with resolution disabled, but it does not include distribution-artifact hashes. The repository therefore does not claim cryptographic provenance for every third-party wheel or source archive. CI action dependencies are separately pinned to full commit SHAs.

The hardened Guardian blocks the included fixed and seeded attack distribution. This does not establish completeness against unknown attack classes.

The defensive loop is bounded and review-gated. It minimizes discovered traces, constructs and evaluates a generalized candidate, and requires that candidate to match the reviewed checked policy before retention. It does not synthesize arbitrary verified policies.

A signed evidence bundle establishes integrity relative to the signing key and its signed checkpoint. It detects tail truncation relative to that checkpoint, but a stateless verifier cannot distinguish an older, previously valid signed bundle from the latest bundle. Rollback detection therefore requires external freshness state or a trusted checkpoint anchor. It also cannot establish semantic correctness when a trusted component is wrong. Compromise of the signing key defeats the policy-attestation and evidence trust boundaries.

A lower-level tool can also violate its declared contract. The checked negative experiment deliberately creates a tool that performs an undeclared actuator side effect during an authorized file read. The Guardian cannot constrain behavior that is absent from the tool interface and state model.

The aggressive-policy experiment shows the opposite failure mode. Blanket restrictions can reduce useful task completion even when they reduce available authority.

The initial proxy confused-deputy result remains the principal policy-composition failure. Valid outer proxy authority is insufficient when the lower-level tool can exercise hidden nested authority. The hardened architecture closes the included proxy class by requiring a separately scoped nested capability and recursively mediating the nested action through Guardian. This does not prove that every possible higher-order tool composition or external tool implementation is correctly modeled.
