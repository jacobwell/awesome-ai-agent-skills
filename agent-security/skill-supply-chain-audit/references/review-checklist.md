# Static review checklist

Load this reference for a full audit or when assigning severity.

## Provenance and integrity

- Resolve the exact source, version, commit, publisher claim, release date, and license.
- Hash every regular file and record the canonical package-manifest hash; note missing, unverifiable, or changing artifacts.
- Identify generated, vendored, minified, encoded, encrypted, binary, or archived content.
- Inspect ZIP/TAR member metadata without extraction. Check member names for absolute paths, drive paths, parent traversal, links, and special entries; bound member count, member size, declared total expansion, and compression ratio.
- Resolve every file in the scanner's `content_review_queue` using a bounded read-only chunked/manual review, or retain it as an explicit disposition-blocking coverage gap.
- Compare the release with a known-good baseline and upstream source when available.

## Instruction integrity

- Does metadata describe the actual behavior and activation scope?
- Can retrieved content, filenames, comments, issue text, or documents become instructions?
- Do instructions request secrecy, authority bypass, false completion, or skipped verification?
- Are approval gates preserved for external writes and high-impact actions?
- Are users told when information is inferred, unverified, stale, or incomplete?

## Code and installation

- Enumerate entry points, executable bits, interpreters, lifecycle hooks, and subprocesses.
- Review dynamic execution, deserialization, templated shell commands, and unsafe temporary files.
- Review deletes, overwrites, permission changes, persistence, and writes outside the target.
- Review network domains, redirects, uploads, telemetry, webhooks, and remote installers.
- Review credential stores, environment variables, browser/session data, and cloud metadata access.
- Review manifests, lockfiles, dependency sources, version ranges, hashes, and name confusion.

## Tools and MCP

- Match each declared tool to a necessary user-visible capability.
- Verify server ownership, transport security, authentication scope, and data retention.
- Check whether tool output is treated as untrusted data.
- Require confirmation for messages, deployments, purchases, account changes, and destructive writes.

## Data and privacy

- Map collected fields, purpose, destination, retention, and deletion path.
- Minimize access to personal, confidential, regulated, or customer data.
- Distinguish local processing from upload or third-party processing.
- Check logs, caches, crash reports, and generated artifacts for secret leakage.

## Severity

- **Critical:** credible path to arbitrary execution, credential theft, destructive action, covert persistence, or material exfiltration without a meaningful prerequisite.
- **High:** major confidentiality, integrity, authority, or availability impact with realistic prerequisites.
- **Medium:** bounded impact, meaningful hardening gap, or permission expansion requiring multiple conditions.
- **Low:** limited weakness, clarity issue, or defense-in-depth gap.
- **Informational:** inventory fact or improvement with no demonstrated security impact.

Severity describes impact and likelihood; confidence describes evidence quality. Do not combine them. Separately label the claim itself `observed`, `inferred`, or `unknown`.

## Minimum finding record

For each finding include: ID, title, severity, confidence, claim status (`observed`, `inferred`, or `unknown`), remediation status, evidence with file and line or hash, behavior, exploit prerequisites, impact, affected versions, remediation, verification step, and residual risk.
