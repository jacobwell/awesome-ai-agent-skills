# MCP server design checklist

Use this checklist selectively. Confirm version-sensitive requirements against the current MCP specification and the chosen SDK. Last verified against the stable `2026-07-28` specification on 2026-08-09.

## Current revision checkpoint

- `2026-07-28` removes the `initialize`/`notifications/initialized` exchange and `Mcp-Session-Id`; do not build a new current-revision server around either.
- Implement `server/discover`. Carry protocol version and client capabilities in `_meta` on every request; use the required Streamable HTTP routing headers and reject header/body mismatches.
- Include `resultType` in every result. Implement `input_required` and retry-carried responses when Multi Round-Trip Requests are needed.
- Return deterministic list order plus required `ttlMs` and `cacheScope` on cacheable list/read results.
- Treat initialize/session verification as a separate legacy-compatibility suite only for older revisions the server deliberately advertises.

## Scope and trust boundaries

- State the user job and explicit non-goals.
- Inventory hosts, clients, server components, downstream systems, and trust boundaries.
- Classify input, output, logs, resources, prompts, and sampled content by sensitivity.
- Identify all direct, indirect, and externally visible effects for every tool; use a list because one operation can read private data, change access, and send externally.
- Inventory every handled data class, including `none`, public, internal, confidential, restricted, personal, financial, health, and credentials.
- Record whether the server is single-user, multi-user, or multi-tenant.

## Tool contracts

- Use a stable action-oriented name that is not confusable with another tool.
- Describe the operation, required authority, effect, and important limitations.
- Define an object input schema and constrain strings, numbers, arrays, enums, and formats.
- Make `required` fields match implementation and reject invalid combinations.
- Bound collection sizes, text lengths, result limits, time ranges, and recursion.
- Define a compact structural success schema and return matching `structuredContent`.
- Define stable caller-safe error codes with structural error-data schemas for invalid input, unauthenticated, forbidden, conflict, rate limited, unavailable, timeout, and internal failure.
- Declare an authorization mode for every tool. Use explicit `public` only when unauthenticated access is intended; otherwise name scopes and the deterministic enforcement point.
- Compare descriptions against declared effects. Words such as delete, execute, send, charge, grant access, or fetch externally should trigger review when the matching effect is absent.
- Document pagination, cancellation, retry safety, and idempotency.
- Separate preview/draft from commit/apply for consequential operations.
- Do not treat tool annotations as a security boundary.

## Resources and prompts

- Give resources stable identifiers and explicit media types.
- Authorize each resource read independently; do not infer permission from discoverability.
- Bound resource size and defend against path traversal, SSRF, and cross-tenant access.
- Treat resource contents and prompt arguments as untrusted data.
- Avoid embedding secrets or privileged instructions in resources or prompt templates.

## Transport and lifecycle

- Choose `stdio` for a local child process or remote HTTP for a network service based on actual client requirements.
- Keep protocol output separate from diagnostic logging, especially on `stdio`.
- Implement clean startup, discovery, shutdown, cancellation, and connection cleanup. For `2026-07-28`, verify stateless per-request behavior rather than a protocol session lifecycle.
- Bound deadlines, concurrency, queue depth, payload size, and downstream response size.
- Add health/readiness checks that do not leak sensitive configuration.

## Identity and authorization

- Authenticate the caller and validate issuer, audience, expiry, and signature as applicable.
- Enforce tenant-, object-, field-, and action-level authorization server-side.
- Use minimum scopes and short-lived credentials.
- Keep MCP access tokens out of logs, resources, errors, and model context.
- Never pass an inbound MCP token through to a downstream API; obtain a separate audience-bound token.
- Bind consequential approval to actor, action, normalized parameters or digest, expiry, and nonce.
- Return indistinguishable missing/forbidden responses when object enumeration is a risk.

## Reliability and observability

- Use safe timeouts and retries only for idempotent operations.
- Apply backpressure and rate limits per actor and tenant.
- Attach a correlation ID to calls and downstream requests.
- Record actor, tool, target class, decision, effect, latency, and outcome in audit events.
- Redact secrets, credentials, personal data, prompts, and raw records by default.
- Define service-level indicators for availability, error rate, latency, denials, and downstream saturation.

## Verification matrix

- On `2026-07-28`, call `server/discover`, verify per-request version/client metadata, and reject unsupported versions.
- On Streamable HTTP, verify `Mcp-Method` and `Mcp-Name` match the JSON-RPC body and confirm no `Mcp-Session-Id` dependency.
- On explicitly supported older revisions, test initialize/initialized and session behavior in a separate compatibility suite.
- List tools/resources/prompts and compare advertised schemas to implementation.
- Verify required `resultType`, deterministic list ordering, `ttlMs`, `cacheScope`, and MRTR retry semantics where applicable.
- Exercise successful calls and every documented error.
- Test missing and extra fields, wrong types, boundary values, oversized values, and malformed encodings.
- Test absent, expired, wrong-issuer, wrong-audience, and insufficient-scope credentials.
- Test cross-tenant and unauthorized object identifiers.
- Test downstream timeout, unavailable, rate-limited, malformed, and partial responses.
- Test cancellation, duplicate delivery, retry, and idempotency behavior.
- Review logs and traces for sensitive data.
- Verify rollback and credential revocation in a non-production environment.

## Primary MCP references

- [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP 2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [MCP 2026-07-28 discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)
- [MCP 2026-07-28 transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [MCP 2026-07-28 authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
- [OAuth 2.0 Protected Resource Metadata, RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)
