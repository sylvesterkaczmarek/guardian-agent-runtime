# Guardian Agent Runtime

Guardian checks an agent's proposed tool calls against permissions, policy and current system state before dispatch. It signs a record linking the decision to the reported result and observed effects.

## Cite the observed-outcomes pilot

Kaczmarek, S. (2026). *Guardian Agent Runtime* (v0.5.0) [Software]. Zenodo. [10.5281/zenodo.24409069](https://doi.org/10.5281/zenodo.24409069)

[Citation metadata](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/blob/59bdeef7c509068b6f628f7ab5e2c61fa6161fac/CITATION.cff) · [Two-page research note](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/blob/v0.5.0/docs/observation-pilot.pdf) · [Frozen protocol](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/blob/v0.5.0/docs/observation-study-protocol.md) · [Case-level results](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/blob/v0.5.0/results/observation_pilot.json)

## Run the pilot

With Python 3.12 or later in a fresh environment, run:

```bash
python -m pip install guardian-runtime-assurance==0.5.1
guardian-study --output pilot
```

The report compares tool acknowledgements with observed outcomes on a file worker and a simulated joint. Guardian and the simple checker agreed on all 126 decisions. Each correctly resolved 52 claims and left 74 unknown. Version 0.5.1 corrects the package description and reproduces the archived v0.5.0 report.

[Runtime and integration guide](https://github.com/sylvesterkaczmarek/guardian-agent-runtime/blob/v0.5.0/docs/observed-outcomes.md)
