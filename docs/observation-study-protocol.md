# Observation contract study protocol

Local development pilot. The development workflow is a software joint moving to position 3. The transfer workflow is a separately implemented subprocess file worker committing the value 4. Freeze these predictions before examining file-worker results. Both backends expose one parent operation and a separately authorised child. The bounds [0,5] apply to the committed integer state throughout each discrete workflow.

| Evidence available to the evaluator | Final value equals target | Final value inside bounds | All committed states inside bounds |
|---|---|---|---|
| Tool acknowledgement alone | Unknown | Unknown | Unknown |
| Fresh terminal observation | Decidable | Decidable | False if terminal value violates, otherwise unknown |
| Complete transition observations including terminal state | Decidable | Decidable | Decidable |
| Missing or stale terminal sample, partial history | Unknown | Unknown | False if an observed value violates, otherwise unknown |

Compare an acknowledgement-based reference scorer, a simple checker using the same observations, and Guardian's signed, parent-linked observations on identical executions. Compare fresh executions against a state- and parameter-aware admission baseline using the same admissible target range and initial-state rule. Freeze the held-out implementation and its workflow separately from the decision functions. Conditions are normal completion, acknowledged no-op, committed change with reported failure, temporary excursion, persistent out-of-range state, delayed observation and missing observation. Include a refused out-of-range command as a separate prevention control. The hidden scorer reads the full history. Evaluators only receive their assigned observation and its freshness/completeness flags.

Report per-family raw paired counts, false confirmations, false denials, missed violations (including unknown), unknowns, correct resolutions among predicted-answerable cases, observed benign completion and host-specific p95 timing. The initial comparison is a deterministic pilot with one implementation per family. Repeats within the same family do not provide independent sampling uncertainty.

For a later independently authored study, use the paired implementation/workflow family as the unit of analysis. The candidate must halve false confirmations relative to the best equal-information baseline, resolve at least 90% of answerable claims, and lose no more than five percentage points of benign completion on each backend. If the baseline makes zero false confirmations, require higher correct resolution at the same error level. A tie favours the simple checker. For a future estimate with a two-sided 95% Wilson interval of approximately ±10 percentage points around a family-level proportion, budget at least 97 independent families under worst-case variance, then size the paired comparison using observed discordance. Do not infer population uncertainty from the two pilot implementations.
