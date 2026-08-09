# Approval gate design guide

Use this guide to make policy decisions explicit. Adapt thresholds to the owner's actual policy; examples are not authority.

## Risk dimensions

Assess each action across:

- **Impact:** negligible, limited, material, severe
- **Reversibility:** automatic, manual, difficult, irreversible
- **Scope:** one object, one user, a cohort, an organization, public
- **Sensitivity:** public, internal, confidential, restricted
- **Authority:** ordinary, privileged, administrative, legal/fiduciary
- **External effect:** none, communication, transaction, access change, physical effect
- **Uncertainty:** known/validated, bounded, material unknowns, insufficient evidence
- **Detection:** immediate, delayed, unlikely, unknowable

Document the dominant reason for the tier. Do not average away a severe dimension.

## Gate selection heuristics

| Profile | Typical control |
|---|---|
| Bounded, reversible, low impact | Autonomous plus audit |
| Low impact but useful awareness | Notify after action |
| Material, externally visible, or hard to reverse | Review before action |
| Risk changes at a measurable threshold | Step-up approval |
| Critical privilege, irreversible effect, or strong policy duty | Dual control by at least two distinct subjects |
| Outside policy or unacceptable residual risk | Prohibit |

## Decision package

An approver should be able to answer:

1. What exact action will happen?
2. Who or what will it affect?
3. Why did the agent propose it and why is review required?
4. Which evidence supports it, how fresh is that evidence, and what is missing?
5. What are the material risks, cost, uncertainty, and reversibility?
6. What alternatives exist?
7. What will reject, edit, cancel, or timeout do?

Use a before/after diff for updates. For a batch, show the aggregate effect and allow item-level inspection; do not hide heterogeneous actions behind one approval.

## Approval binding

Bind a decision to a canonical representation containing:

- Workflow and proposal ID
- Tenant and requesting actor
- Action and target identifiers
- Material normalized parameters or their cryptographic digest
- Policy and application versions
- Creation and expiry times
- One-time nonce

Record approver identity, role at decision time, decision, reason, timestamp, and bound proposal digest. Revalidate identity, role, policy, target state, and preconditions immediately before execution.

Keep roles and people separate in the machine-readable policy. A quorum of two roles is not dual control if both roles resolve to one subject. Make `minimum_distinct_subjects` explicit and test the actual eligible-subject set.

## Predicate and exception structure

Represent gate conditions as a bounded predicate tree rather than arbitrary text. Use logical `all`, `any`, or `not` nodes, or a leaf with exactly `field`, `op`, and `value`. Validate field names, comparison types, regular expressions, nesting depth, and empty sets before accepting a policy.

Reject critical single-control and requester self-approval by default. An exception must be a separate, time-bounded waiver with:

- Gate ID and exception type (`critical-single-control` or `self-approval`)
- Stable policy-owner subject and approval reference
- Approval and expiry timestamps
- Specific rationale and compensating controls
- An explicit waiver reference on the affected gate

Do not infer a waiver from a comment, role name, or model output.

## Required failure behaviors

- **Escalation:** delay, target roles, maximum attempts, and deny/cancel/block behavior after exhaustion
- **Audit outage:** fail closed, or use a short signed buffer only where policy permits; critical gates fail closed
- **Reauthorization:** recheck at execution and invalidate on proposal, policy, role, target-state, or expiry changes
- **Compensation:** mode, accountable subject, runbook reference, and documented limitation when unavailable or inapplicable
- **Break-glass:** explicit enablement, at least two stable subjects, narrow scope, short expiry, required reason, immediate notice, and after-action review

## State machine invariants

- Only a prepared proposal can enter review.
- Only authorized decisions satisfying quorum can approve.
- Rejection, cancellation, or expiry can never transition to executing.
- Material edits create a new proposal or digest and invalidate prior decisions.
- Approval can be consumed once.
- Execution records the bound proposal and resulting downstream operation ID.
- Retries cannot duplicate an effect.
- Partial failure enters an explicit state; it is never reported as complete.

## Audit record fields

Capture:

- Event and correlation IDs
- Workflow, proposal, policy, and version IDs
- Tenant, requester, approver role and stable subject ID
- Action, target class, proposal digest, risk tier, and gate reason
- Decision, reason, timestamps, expiry, quorum state, and escalation history
- Execution attempt, downstream operation ID, outcome, and compensation state

Avoid raw secrets, tokens, full sensitive documents, or unnecessary personal data. Define retention, access, integrity, export, and deletion rules with the policy owner.

## Operational tests

- Stale tab and changed target state
- Multiple simultaneous approvers
- Self-approval, quorum bypass, and two required roles resolving to one subject
- Critical single-control with no waiver, wrong-owner waiver, expired waiver, and a waiver not referenced by its gate
- Duplicate webhook or button submission
- Approver loses role after viewing but before deciding
- Policy changes while pending
- Approval expires during execution dispatch
- Notification provider outage
- Audit storage unavailable
- Escalation exhausted with no covering approver
- Downstream accepts request but client times out
- Compensation fails
- Break-glass replay, overbroad scope, expiry, or missing after-action review

## Primary references

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [NIST AI RMF Appendix C: Human-AI Interaction](https://airc.nist.gov/airmf-resources/airmf/appendices/app-c-ai-risk-management-and-human-ai-interaction/)
