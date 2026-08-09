# Security Policy

## Report a Vulnerability

Do not publish working exploits, credentials, private data, or prompt-injection payloads that could harm users in a public issue.

Use the repository's **Security → Report a vulnerability** flow when it is available. If private reporting is unavailable, contact the maintainer through the GitHub profile and request a private channel before sharing sensitive details.

Include:

- affected skill and revision;
- impact and realistic attack path;
- minimal reproduction with secrets removed;
- suggested mitigation, if known;
- whether the issue is already public or actively exploited.

General quality problems without sensitive exploitation details may be reported through a normal issue.

## Scope

Security reports may cover malicious or unsafe instructions, prompt-injection exposure, secret handling, destructive commands, data exfiltration, excessive permissions, dependency or supply-chain risks, and misleading safety claims.

This project contains instructions that agents may execute in different environments. Users should inspect skills, understand requested permissions, and test in an isolated environment before relying on them for sensitive or production work.
