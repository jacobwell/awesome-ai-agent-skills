# Agent trace schema

Read this reference when defining span fields, redaction, or telemetry cardinality.

## Required span fields

| Field | Meaning |
| --- | --- |
| `trace_id` | Identifier for one user-visible attempt |
| `span_id` | Identifier unique within the trace |
| `parent_span_id` | Parent identifier; omit only for the root |
| `name` | Stable operation name such as `model.generate` |
| `start_ms`, `end_ms` | Numeric timestamps in the same clock domain |
| `status` | `ok`, `error`, or `unset` |

Recommended fields include `agent_version`, `model`, `tool`, `attempt`, `tokens_input`, `tokens_output`, `cost_usd`, `policy_outcome`, and a bounded `error_type`. Store large or sensitive payloads outside spans only when an approved investigation requires them.

## Summarizer semantics

Run `python3 scripts/summarize_traces.py spans.jsonl`. The command returns:

- `0` when every trace has exactly one root, all parent references resolve, no parent cycle exists, and each trace is one connected component;
- `1` when any of those structural checks fails;
- `2` for unreadable input, invalid JSON, duplicate span identities, invalid fields, invalid timestamps, or an unsafe or unwritable `--output` target.

`structure.structurally_valid` means only that those graph checks passed. `trace_observed_envelope_ms` is the maximum observed end minus minimum observed start within each trace; it is not a causal end-to-end duration. The output cannot prove that instrumentation is complete.

The summarizer audits raw field names and limited secret-like value patterns before discarding payloads. It reports only trace ID, span ID, field path, and reason under `sensitive_field_audit`; it never copies the suspected value. Add `--strict` to return `1` when any such finding exists. This heuristic catches common mistakes but does not certify redaction or privacy compliance.

## Naming and cardinality

- Use low-cardinality span names based on operations, not user or document identifiers.
- Put dynamic values in attributes and hash identifiers only when the hash still meets privacy policy.
- Use consistent units in field names, such as `latency_ms` and `cost_usd`.
- Version the schema when field meaning changes.
- Bound values such as error type, tool name, model, tenant tier, and region.

## Redaction order

1. Avoid collecting content.
2. Allowlist necessary fields.
3. Redact secrets and regulated identifiers before export.
4. Enforce access, regional storage, and retention controls.
5. Test with seeded canary values.

Redaction after ingestion can be too late. Apply it in the process that first observes the data when practical.

## Metrics from spans

- End-to-end latency: root end minus root start, or trace maximum end minus minimum start when the root is missing.
- Tool error rate: failed tool spans divided by completed tool spans.
- Task success rate: successful user outcomes divided by eligible attempts, measured from a verifier rather than HTTP status alone.
- Cost per completed task: total attributed cost divided by verified completed tasks.

Keep the span-to-metric query with the metric definition. Specify how retries, cancellations, cached calls, and partial traces affect each denominator.

## Script input

`scripts/summarize_traces.py` accepts one JSON span per line using the required fields above and optional `tool`. It validates duplicate span identifiers, durations, and parent references, then emits aggregate timing and error statistics without copying raw attributes.
