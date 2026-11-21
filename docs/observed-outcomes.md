# Observed outcomes

## Run the offline experiment

Install with `python -m pip install guardian-runtime-assurance==0.5.0`, then run `guardian-study --output pilot`. Add `--timing` for host-specific p95 timing. The output includes a paired JSON report and one signed sample bundle, manifest and example public key for each backend. The reference examples use published deterministic signing keys. Integrations supply their own trusted keys.

The experiment covers a discrete joint simulator and a subprocess that commits values to a disposable file. Each parent operation has two separately authorised children. A reader in the parent process observes committed file bytes after each synchronised transition. The scorer retains the full history. Guardian receives only the projection declared by the observer. Evidence about a trajectory applies to this discrete observation model. The pilot makes no claim about continuous physical motion or disk crash durability.

| Per backend | Reference acknowledgement scorer | Simple checker, same observations | Guardian, signed observations |
|---|---:|---:|---:|
| False confirmations / 63 claim decisions | 6 | 0 | 0 |
| False denials / 63 | 3 | 0 | 0 |
| Unknown / 63 | 42 | 37 | 37 |
| Actual violations missed, including unknown / 15 | 15 | 6 | 6 |
| Correct on predicted-answerable cases / 26 | 4 | 26 | 26 |

The acknowledgement scorer grades completion only. The other two scorers could decide all 26 predicted-answerable claims on each backend. Both left 37 unknown, including six actual violations. The simple checker tied Guardian on every verdict. Guardian additionally authenticates the recorder's statements and links each observed child to its authorised parent. The preregistered superiority criterion was not met. Each admission system completed the normal workflow on each backend and refused both the out-of-range and unavailable-state controls before tool invocation. Internal tool faults can still produce unwanted effects after admission.

The [initial pilot revision](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/commit/2ad687c5919e7663305b491a961e06dbc717d084) recorded one timing run using Python 3.12.14 on Linux x86-64, with 21 paired dispatches per backend. The p95 of the paired Guardian-minus-baseline time was 2.79 ms for the simulated joint and 10.31 ms for the file worker. Standalone signed-claim verification p95 was 1.42 ms and 2.27 ms respectively. These include ordinary host scheduling noise. Runtime construction is excluded, and the file workflow includes subprocess startup. Use `--timing` to measure your machine.

Each backend contributes seven conditions observed through three views. The 63 decisions concern three properties for each of 21 executions. They are correlated observations on one implementation. The frozen plan gives the independent replication design. Each report row contains the task truth, predicted answerability, visible samples, actual verdicts and the independently executed state-aware baseline's committed history. The separate reference-task section records all eleven benign fixtures and two write controls. The acknowledged no-op fails completion. The write followed by an exception succeeds on the final-state postcondition and retains the reported tool failure.

[Paired results](../results/observation_pilot.json) · [Frozen protocol](observation-study-protocol.md) · [Frozen protocol commit](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/commit/66628445f799507a9037926065a3c79aff533db5)

## Add a tool

The v1 adapter contract is a Python object with `snapshot()`, `check_invariants(request)` and `execute(request)`. Return a monotonic state version and the state used by policy rules. Privileged credentials belong to the trusted adapter. For a composite, declare its operation name and implement `build_nested_requests(request)` returning an ordered, nonempty tuple of child requests. Every child carries its own capability and nonce and retains the parent subject and session. The gateway obtains a fresh decision before each child. It stops at the first failed child and propagates its status. Earlier committed steps remain visible. The per-operation limits are 64 children and 16 nested composite levels.

```python
from time import time
from guardian_runtime.adapters import AdapterSpec, EffectObserver
from guardian_runtime.factory import build_integration

runtime, signed_manifest, _ = build_integration(
    "my-tools",
    environment=adapter,
    adapter=AdapterSpec.from_file("my-tools-v1", adapter_build_artifact, ("publish_batch",)),
    signing_key=private_key,
    clock=lambda: int(time()),
    clock_policy="deployment-utc",
    permit_ttl_seconds=5,
    policy_path="policy.yaml",
    capability_path="capabilities.yaml",
    observer=EffectObserver("destination-reader-v1", read_destination),
)
decision, result = runtime.execute_request(proposal)
bundle = runtime.evidence.export_bundle(policy_version=runtime.policy.version)
```

Supply the adapter build artifact or a deployment-verified SHA-256 digest covering its code and relevant configuration. The manifest binds that declaration, the composite names, clock policy, permit lifetime, signer, observer identity, policy and capability bytes. A trusted deployment must still check that the installed adapter matches the declared build. The observer callback takes a detached request and result. Read the destination through an independent channel. Return a JSON mapping of readings. Guardian signs these readings as recorder evidence. A missing or failed observer leaves the tool result and a signed unavailable observation. A separately authenticated sensor can be supplied by an integrator. The packaged worker and simulator demonstrate the contract without requiring credentials. [Runnable adapters](../src/guardian_runtime/study/workflows.py)

## Inspect and replay

Install the optional dependency with `python -m pip install '.[inspect]'` from the checkout. A wheel install can use its local path followed by `[inspect]`. Run the following from any directory.

```bash
inspect eval guardian_runtime/observation_contract --model mockllm/model
```

The default solver replays the 14 provided proposals offline. To replay your own, add `-T proposals=records.json`. Each record contains a family, a fixture condition and a normal Guardian action request. For example, save the following as a JSON array.

```json
[{"family":"file","mode":"normal","proposal":{"subject":"study-agent","session_id":"offline-trial","tool":"study","action":"commit_batch","params":{"target":4},"purpose":"study","capability_id":"parent-file","nonce":"my-run-1"}}]
```

A team can supply an Inspect solver that outputs one action request as JSON, or use `-T live=true` with its configured model. For example, a Python evaluation can pass its solver via `eval(observation_contract(), solver=my_solver, model=my_model)`. The dataset fixes the operation, goal and fixture condition for scoring. A proposal for a different operation scores zero before dispatch. A proposal for another value is evaluated against the original goal. The score records admission, tool acknowledgement, destination completion and the signed-observation verdict. These are tool-conformance fixtures with a specified operation. They measure neither model reasoning ability nor agent robustness.

## Verify and reproduce

For a local format check with the pilot's public demonstration key, run these commands from the directory containing `pilot/`.

```bash
TRUSTED_KEY=$(cat pilot/file/public-key.txt)
EXPECTED_HASH=$(python -c 'import json; print(json.load(open("pilot/file/manifest.json"))["manifest_hash"])')
```

For an independent deployment check, obtain the trusted public key and expected manifest hash from the deployment owner through a separate channel. Both checks use the same verifier commands.

```bash
guardian-verify-manifest pilot/file/manifest.json --public-key "$TRUSTED_KEY" --manifest-hash "$EXPECTED_HASH"
guardian-verify pilot/file/bundle.json --public-key "$TRUSTED_KEY" --manifest-hash "$EXPECTED_HASH"
```

The v2 event adds tool status, a permit fingerprint, the enclosing permit fingerprint and any observer readings. Children appear before their enclosing operation in the signed chain. The verifier resolves the links within the same bundle, subject and session. Version 1 records continue to verify using their original signed bytes. A signed bundle authenticates its contents under the supplied key. Detecting rollback still requires an external freshness anchor.

`make verify-reproduce` regenerates and compares the deterministic artifacts. The original v0.4.1 results and verifier are preserved at the published tag. To reproduce those bytes, use a separate checkout of that tag and its dependency lock. [v0.4.1 baseline](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/tree/v0.4.1)
