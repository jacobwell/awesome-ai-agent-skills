---
name: your-skill-name
description: State what the skill does, its concrete inputs or artifacts, and the user requests that should activate it. Use when the user mentions specific trigger phrases or needs this exact workflow; distinguish neighboring skills when overlap is likely.
---

# Your Skill Name

State the outcome this skill helps an agent produce. Keep instructions imperative, task-specific, and concise.

## Required Inputs

- List required files, data, goals, constraints, and decisions.
- State which missing inputs block work and which permit documented assumptions.

## Output Contract

Define the deliverables, format, required evidence, and completion criteria.

## Workflow

1. **Inspect context.** Reuse project conventions and identify constraints.
2. **Plan the work.** Select the safest reliable method and state assumptions.
3. **Execute incrementally.** Preserve originals and keep changes reviewable.
4. **Verify the result.** Run deterministic checks and inspect the actual output.
5. **Report clearly.** Summarize outcomes, evidence, limitations, and next actions.

## Safety and Permissions

- Start with read-only inspection.
- Require explicit authorization before external writes, destructive actions, deployments, purchases, messages, filings, or access to sensitive data.
- Preserve a rollback or recovery path for material changes.
- Add domain-specific boundaries for legal, medical, financial, compliance, security, and other high-impact work.

## Verification

- Define checks that prove the output works rather than merely exists.
- Test scripts and executable examples.
- Record failures honestly and distinguish verified facts from assumptions.

## Failure Handling

Explain how to respond to missing tools, malformed inputs, partial results, and unsafe requests. Prefer a safe fallback or a precise blocker over fabricated success.

## Example

**Request:** Provide a realistic trigger prompt.

**Expected result:** Describe the artifact and verification evidence the skill should produce.

## Optional Resources

- Put deterministic or repeatedly rewritten operations in `scripts/` and test them.
- Put detailed, selectively loaded guidance in `references/` and link it directly from this file.
- Put templates or files copied into outputs in `assets/`.
- Add `agents/openai.yaml` only when maintaining Codex-specific UI metadata.
