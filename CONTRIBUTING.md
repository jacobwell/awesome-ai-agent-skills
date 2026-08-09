# Contributing to Awesome AI Agent Skills

Thank you for improving the library. Contributions should add reusable procedural value, not merely increase the catalog count.

## Before You Start

1. Search the existing catalog for the same trigger and outcome.
2. Open or comment on an issue before adding a new category or a skill that substantially overlaps an existing one.
3. Keep the universal core platform-agnostic. Put vendor-specific commands behind clearly labeled variants or propose them separately.
4. Use lowercase kebab-case for the directory and frontmatter `name`; they must match exactly.

## Create or Update a Skill

1. Choose the closest category and copy [`SKILL_TEMPLATE.md`](./SKILL_TEMPLATE.md) into `<category>/<skill-name>/SKILL.md`.
2. Write a description that says what the skill does and explicitly says **Use when** with concrete user wording, inputs, or artifacts. Add an overlap boundary when a neighboring skill could trigger.
3. Define required inputs, output contract, workflow, permission boundaries, failure behavior, and verification evidence.
4. Add only reusable resources that improve execution:
   - `scripts/` for deterministic or repeated operations
   - `references/` for selectively loaded standards, schemas, and detailed variants
   - `assets/` for templates and files copied into outputs
5. Test every executable script and example. Do not include credentials, private data, copied proprietary material, or claims that were not checked.
6. Add the skill to the README index and update the `<!-- skill-count: N -->` marker.

## Safety Requirements

- Require explicit authorization before active security testing, destructive operations, deployments, database writes, external messages, purchases, filings, or changes to third-party systems.
- Start with read-only inspection and dry runs where available.
- Preserve originals and document rollback for material changes.
- For legal, medical, financial, compliance, and other high-impact domains, cite dated authoritative sources, state uncertainty, and require qualified human review.
- Never claim a task succeeded without verifying the resulting artifact or external state.

## Validate Locally

Run the repository validator before submitting:

```bash
python3 scripts/validate_skills.py
```

The validator checks naming, activation descriptions, structure, local links, duplicate files, README synchronization, skill count, Python script syntax, and Codex UI metadata when present. CI runs the same command on every pull request.

For a new or materially revised skill, also test at least two realistic prompts:

- one normal task that should activate the skill and complete successfully;
- one edge or failure case that exercises its permission, recovery, or uncertainty handling.

Include the prompts, observed behavior, and any script commands in the pull request description.

## Pull Request Checklist

- [ ] The contribution is original, licensed for inclusion, and does not duplicate an existing skill.
- [ ] The directory and frontmatter names match and use lowercase kebab-case.
- [ ] The description contains explicit **Use when** activation guidance.
- [ ] Inputs, outputs, safety boundaries, failure handling, and verification are concrete.
- [ ] Scripts and executable examples were actually run.
- [ ] Changing facts cite authoritative sources with a verification date.
- [ ] README links and the exact skill count are updated.
- [ ] `python3 scripts/validate_skills.py` passes.

## Code of Conduct

Be respectful, specific, and constructive. Review the work, not the person.
