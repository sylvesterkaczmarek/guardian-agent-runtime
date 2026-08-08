# Method

Every request is canonicalized before authorization. A capability constrains subject, session, tool, action, resource, parameters, validity period, invocation count, purpose, nonce, and delegation. Policy rules then impose deployment-level restrictions. Environment invariants provide a separate safety boundary.

Capability validation is first performed without consuming authority. Policy and invariant checks then run. Only a request that passes all three stages reserves its nonce and invocation budget and receives an Ed25519-signed execution permit. This prevents policy-denied requests from exhausting legitimate capability budgets.

The tool gateway verifies the permit signature and bindings, rejects replayed or expired permits, checks current capability and ancestor revocation status, checks state version, and re-evaluates safety invariants immediately before execution.

Every request submitted through `execute_request` produces signed evidence. Successful gateway executions and modeled lower-level tool exceptions are recorded from the gateway boundary. Events are hash chained and signed. Exported evidence bundles also contain a signed checkpoint with event count and terminal hash so tail truncation relative to that checkpoint can be detected.

The defensive experiment searches fixed and seeded adversarial scenarios, reproduces successful bypasses, greedily minimizes multi-step traces, groups distinct minimized routes, and constructs a generalized candidate. For the checked proxy failure class, the candidate removes borrowed nested authority by requiring an explicit nested capability and recursively routing the nested privileged request through Guardian authorization, policy evaluation, invariants, permit issuance, and evidence generation. It is evaluated against the adversarial and benign workloads and retained only when security improves without a benign completion regression or new benchmark failure. The generated candidate must also match the reviewed checked policy before retention.

Generated minimized cases are serialized to `results/generated_regressions.json`. The regression test suite loads that checked artifact and executes each case against the hardened Guardian.

The hardening mechanism is deliberately bounded. It does not claim arbitrary policy synthesis or proof of policy completeness.
