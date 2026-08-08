# Threat model

## Assets

- authority to invoke privileged tools
- Guardian policy and capability definitions
- Guardian signing keys
- mission and sandbox state
- execution evidence and checkpoints
- mock secrets in the local sandbox

## Trust boundaries

The agent, prompts, retrieved content, tool output, and proposed actions are untrusted. The Guardian policy, capability store, signing key, reference-monitor logic, and declared tool contracts are trusted for the principal experiment.

The lower-level sandbox contains one intentional proxy confused-deputy flaw in the initial-policy experiment. A separate negative test also models a tool that violates its declared contract.

## Adversary capabilities

The benchmark allows the adversary to submit malformed or deceptive requests, reuse nonces, replay signed permits, attempt post-authorization revocation bypass, escalate privileges, route through tools, exploit stale state, induce unsafe parameter values, exploit delegation, and tamper with exported evidence.

## Partially mitigated

- compromised models are constrained at privileged action boundaries, but information-only harm is outside scope
- compromised tools are constrained only to the extent their behavior is represented by the declared interface and state model
- supply-chain risk is made more inspectable through a pinned environment, dependency inventory, SBOM, checksums, and signed manifests, but trustworthy provenance is not proven
- policy incompleteness can be exposed by adversarial evaluation, but completeness is not proven
- replay, revocation, nonce, invocation-budget, rate-limit, and resource-budget state are protected only for the lifetime of the reference process; durable restart semantics require persistent monotonic state or epoch invalidation

## Out of scope

- Guardian signing-key compromise as a protected-key assumption
- compromised host kernel or hypervisor
- arbitrary memory corruption in the Guardian process
- physical attacks
- side-channel and covert-channel elimination
- secure production key storage
- real hardware attestation
- arbitrary real-world network exploitation

The negative-result suite demonstrates that signing-key compromise and hidden tool side effects break important assumptions rather than treating those cases as solved.

The runtime manifest is software-signed. It must not be interpreted as TPM, TEE, secure-element, or confidential-compute attestation.
