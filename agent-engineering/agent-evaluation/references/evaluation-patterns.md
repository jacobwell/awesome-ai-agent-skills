# Evaluation patterns

Read this reference when choosing graders, normalizing result records, or defining a release gate.

## Match the grader to the claim

| Claim | Preferred grader | Guardrail |
| --- | --- | --- |
| Exact value, schema, citation, or tool call | Deterministic assertion | Validate semantics, not formatting alone |
| Open-ended response quality | Rubric-bound model grader | Blind candidate order and audit a human sample |
| Policy or safety compliance | Deterministic checks plus specialist review | Treat any critical miss separately from averages |
| User preference | Randomized human comparison | Report rater count and agreement |
| End-to-end task completion | Environment verifier | Reset state and capture side effects |

Avoid one generic “quality” score. Define observable dimensions and anchor each scale with examples. Use pairwise comparison when absolute scoring is unreliable.

## Case design

- Represent expected traffic and known high-impact risks separately.
- Preserve a stable regression set and a sequestered holdout set.
- Record provenance, consent or license, creation date, category, risk tier, and expected behavior.
- Deduplicate by source identifier and semantic similarity.
- Include dependency failures, timeouts, malformed outputs, and refusal boundaries.

## Normalized result record

Store one JSON object per line:

```json
{"case_id":"refund-017","run_id":"seed-1","variant":"new","category":"policy","score":0.9,"passed":true,"latency_ms":842,"cost_usd":0.013}
```

`case_id` and finite numeric `score` are required by `scripts/aggregate_results.py`. Declare the inclusive scale with `--score-min` and `--score-max` (defaults are 0 and 1); out-of-range scores are rejected. A record identity is `record_id` when supplied, otherwise `(case_id, variant, run_id)`, with missing `variant` normalized to `default` and missing `run_id` treated as a single run. Duplicate identities are rejected, so repeated or stochastic attempts need distinct `run_id` values. Optional `passed`, `latency_ms`, `cost_usd`, and `category` fields enable additional summaries. Use `--require-passed` to reject records missing a pass label.

For a descriptive baseline comparison, label records with `variant` and pass both `--baseline LABEL` and `--candidate LABEL`. The output includes the candidate-minus-baseline mean and, with at least two records per arm, an independent-sample normal-approximation interval. That interval does not account for pairing, clustering, multiple comparisons, or sampling bias; use an analysis matched to the experimental design for inferential claims.

The JSON output uses `structurally_valid: true` only to mean that parsing, identities, types, and declared bounds passed. `pass_rate` always names observed, missing, and total record counts, and its value is calculated only over records with a Boolean `passed` field. The output is descriptive evidence, not a safety or release certification.

## Release gate pattern

Define the gate before viewing candidate results:

- Require all critical safety and authorization cases to pass.
- Require the primary metric to meet an absolute floor.
- Limit regression against the frozen baseline by category.
- Enforce p95 latency and average-cost ceilings when measured.
- Require enough repeated cases to distinguish a real change from run variance.

Report the sample size and excluded records. Do not imply statistical significance from a point estimate alone.
