# Offline Red-Team Rules of Engagement

This file is a **synthetic authorization record for the bundled demo only**. It does not authorize testing any real repository, account, service, model, agent, network, or production environment.

## In scope

- The inert fixtures under `demos/production-agent-stack/fixtures/`
- The local mock boundary implemented by `demos/production-agent-stack/run_demo.py`
- Temporary or explicitly selected local evidence directories created by the runner
- One replay of each of the five documented cases per demo run, with one local boundary assertion per case

## Permitted techniques

- Offline fixture replay
- In-memory proposal, target, requester, timestamp, audit-state, and digest mutation
- One-time approval replay checks against the local in-memory consumption store
- Local structural validation and evidence hashing

## Out of scope and prohibited

- Network requests, target discovery, credential use, model calls, or external APIs
- Live GitHub issues, repositories, CI systems, cloud accounts, or deployment targets
- Real personal, customer, confidential, regulated, or production data
- Destructive actions, persistence, denial of service, social engineering, or data exfiltration
- Uploading generated evidence automatically or representing synthetic approval as a human decision

## Stop and escalation

Stop immediately if a network operation, external effect, real secret, sensitive record, or ambiguous target appears. Terminate the runner, preserve only non-sensitive diagnostic context, and notify the repository maintainer through the process in `SECURITY.md`. The local operator is the emergency owner for deleting partial output.

## Evidence retention

Generated evidence stays local and contains synthetic identifiers only. Temporary output may be deleted after inspection; output written to a chosen persistent directory follows the operator's retention policy. Checksums support local integrity review and are never uploaded by the demo.
