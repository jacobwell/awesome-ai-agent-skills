# MCP server design

## Decision summary

- User job:
- In scope:
- Out of scope:
- Supported clients:
- Transport:
- Protocol revision(s):
- Runtime and SDK:
- Owner:

## Trust and data flow

Describe host, client, server, downstream systems, identities, credentials, trust boundaries, and sensitive data.

## Tool catalog and manifest

| Tool | Purpose | Effects | Data classes | Authorization mode / enforcement | Idempotency | Input / output / error schemas |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

Represent effects and data classes as arrays, even when each contains one value. Give every tool an authorization object; use `mode: public` explicitly rather than omitting authorization. Store machine-checkable `inputSchema`, `outputSchema`, and `errorSchemas` in the JSON manifest. A passing structural lint is not protocol conformance or a safety certification.

## Authorization model

- Authentication:
- Tenant/object/action checks:
- Scopes:
- Downstream token exchange:
- Approval requirements:
- Credential storage and rotation:

## Reliability and limits

- Timeouts:
- Retry policy:
- Concurrency and rate limits:
- Pagination and payload limits:
- Cancellation:

## Verification plan

| Requirement | Test | Expected result | Evidence |
|---|---|---|---|
|  |  |  |  |

For revision `2026-07-28`, include `server/discover`, per-request `_meta`, `Mcp-Method`/`Mcp-Name` header agreement on Streamable HTTP, required `resultType`, cache metadata, and MRTR where applicable. Do not test `initialize` or `Mcp-Session-Id` as the current path; test them only for explicitly supported legacy revisions.

## Operations

- Logs and audit events:
- Metrics and alerts:
- Deployment strategy:
- Rollback:
- Credential revocation:

## Assumptions and residual risk

- Assumptions:
- Unverified items:
- Residual risks and owners:
