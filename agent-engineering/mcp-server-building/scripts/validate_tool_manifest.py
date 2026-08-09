#!/usr/bin/env python3
"""Structurally lint a design-time MCP tool manifest.

Passing this lint means required design fields and JSON Schemas are present. It
does not prove protocol conformance, authorization correctness, or tool safety.
Exercise the implementation with an official SDK and adversarial tests.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
EFFECTS = {
    "none",
    "read",
    "create",
    "update",
    "delete",
    "execute",
    "external-communication",
    "financial-transaction",
    "access-control",
    "network-egress",
}
DATA_CLASSES = {
    "none",
    "public",
    "internal",
    "confidential",
    "restricted",
    "personal",
    "financial",
    "health",
    "credentials",
}
AUTHORIZATION_MODES = {
    "public",
    "authenticated",
    "delegated",
    "service",
    "owner-only",
}
SCHEMA_KEYWORDS = {
    "type",
    "$ref",
    "oneOf",
    "anyOf",
    "allOf",
    "const",
    "enum",
    "properties",
    "items",
    "prefixItems",
    "not",
    "if",
}

# These are deliberately conservative signals. A hit is a warning requiring
# review, not proof that a description is malicious or a declaration is false.
DANGEROUS_DESCRIPTION_SIGNALS: tuple[tuple[re.Pattern[str], set[str], str], ...] = (
    (re.compile(r"\b(delete|erase|purge|destroy|remove permanently)\b", re.I), {"delete"}, "delete"),
    (re.compile(r"\b(execute|run (?:a )?(?:shell|command|script|code)|spawn process)\b", re.I), {"execute"}, "execute"),
    (re.compile(r"\b(send|publish|post|email|message|notify)\b", re.I), {"external-communication"}, "external communication"),
    (re.compile(r"\b(pay|purchase|charge|transfer funds|issue refund)\b", re.I), {"financial-transaction"}, "financial transaction"),
    (re.compile(r"\b(grant|revoke|change) (?:access|permission|role|ownership)\b", re.I), {"access-control"}, "access control"),
    (re.compile(r"\b(fetch|download|upload|call) (?:an? )?(?:url|endpoint|remote|external)\b", re.I), {"network-egress"}, "network egress"),
    (re.compile(r"\b(create|insert|add) (?:a |an )?(?:record|resource|account|item)\b", re.I), {"create"}, "create"),
    (re.compile(r"\b(update|edit|modify|write) (?:a |an )?(?:record|resource|file|item)\b", re.I), {"update"}, "update"),
)


def add(issues: list[dict[str, str]], level: str, path: str, message: str) -> None:
    issues.append({"level": level, "path": path, "message": message})


def lint_json_schema(
    schema: Any,
    path: str,
    issues: list[dict[str, str]],
    *,
    require_object_root: bool,
) -> None:
    if not isinstance(schema, dict) or not schema:
        add(issues, "error", path, "must be a non-empty JSON Schema object")
        return
    if require_object_root and schema.get("type") != "object":
        add(issues, "error", f"{path}.type", "top-level inputSchema type must be object")
    if not any(key in schema for key in SCHEMA_KEYWORDS):
        add(issues, "error", path, "does not contain a structural JSON Schema keyword")
    properties = schema.get("properties")
    if properties is not None and not isinstance(properties, dict):
        add(issues, "error", f"{path}.properties", "properties must be an object")
        properties = {}
    required = schema.get("required")
    if required is not None:
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            add(issues, "error", f"{path}.required", "required must be an array of strings")
        elif isinstance(properties, dict):
            for field in required:
                if field not in properties:
                    add(issues, "error", f"{path}.required", f"required field {field!r} is not defined")
    if require_object_root and schema.get("additionalProperties") is not False:
        add(issues, "warning", path, "consider additionalProperties: false for a narrow input contract")


def lint_string_set(
    value: Any,
    path: str,
    allowed: set[str],
    issues: list[dict[str, str]],
) -> set[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        add(issues, "error", path, "must be a non-empty array of strings")
        return set()
    values = set(value)
    if len(values) != len(value):
        add(issues, "error", path, "values must be unique")
    unknown = sorted(values - allowed)
    if unknown:
        add(issues, "error", path, f"unsupported values: {', '.join(unknown)}")
    if "none" in values and len(values) > 1:
        add(issues, "error", path, "none cannot be combined with another value")
    return values


def lint_authorization(value: Any, path: str, issues: list[dict[str, str]]) -> str | None:
    if not isinstance(value, dict):
        add(issues, "error", path, "authorization must be an object for every tool")
        return None
    mode = value.get("mode")
    if mode not in AUTHORIZATION_MODES:
        add(issues, "error", f"{path}.mode", f"mode must be one of {sorted(AUTHORIZATION_MODES)}")
        return None
    enforcement = value.get("enforcementPoint")
    if not isinstance(enforcement, str) or not enforcement.strip():
        add(issues, "error", f"{path}.enforcementPoint", "must name the deterministic enforcement point")
    scopes = value.get("scopes")
    if mode == "public":
        if scopes not in (None, []):
            add(issues, "warning", f"{path}.scopes", "public mode normally has no authorization scopes")
    elif not isinstance(scopes, list) or not scopes or any(not isinstance(scope, str) or not scope for scope in scopes):
        add(issues, "error", f"{path}.scopes", "non-public mode requires a non-empty string array")
    return mode


def lint_error_schemas(value: Any, path: str, issues: list[dict[str, str]]) -> None:
    if not isinstance(value, list) or not value:
        add(issues, "error", path, "must be a non-empty array of structured error contracts")
        return
    seen: set[str] = set()
    for index, error in enumerate(value):
        error_path = f"{path}[{index}]"
        if not isinstance(error, dict):
            add(issues, "error", error_path, "error contract must be an object")
            continue
        code = error.get("code")
        if not isinstance(code, str) or not ERROR_CODE_RE.fullmatch(code):
            add(issues, "error", f"{error_path}.code", "code must be a stable lowercase identifier")
        elif code in seen:
            add(issues, "error", f"{error_path}.code", f"duplicate error code {code!r}")
        else:
            seen.add(code)
        description = error.get("description")
        if not isinstance(description, str) or len(description.strip()) < 10:
            add(issues, "error", f"{error_path}.description", "description must explain the caller-safe error")
        lint_json_schema(error.get("dataSchema"), f"{error_path}.dataSchema", issues, require_object_root=False)


def lint_manifest(data: Any) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if not isinstance(data, dict):
        return [{"level": "error", "path": "$", "message": "manifest must be a JSON object"}]
    server = data.get("server")
    if not isinstance(server, dict):
        add(issues, "error", "$.server", "server must be an object")
    else:
        for field in ("name", "version", "protocolRevision"):
            if not isinstance(server.get(field), str) or not server[field].strip():
                add(issues, "error", f"$.server.{field}", f"{field} must be a non-empty string")
        if server.get("protocolRevision") == "2026-07-28" and server.get("usesProtocolSessions") is True:
            add(issues, "error", "$.server.usesProtocolSessions", "2026-07-28 removed protocol sessions")
    tools = data.get("tools")
    if not isinstance(tools, list) or not tools:
        add(issues, "error", "$.tools", "tools must be a non-empty array")
        return issues
    seen: set[str] = set()
    for index, tool in enumerate(tools):
        path = f"$.tools[{index}]"
        if not isinstance(tool, dict):
            add(issues, "error", path, "tool must be an object")
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            add(issues, "error", f"{path}.name", "name must use 1-128 safe identifier characters")
        elif name in seen:
            add(issues, "error", f"{path}.name", f"duplicate tool name {name!r}")
        else:
            seen.add(name)
        description = tool.get("description")
        if not isinstance(description, str) or len(description.strip()) < 20:
            add(issues, "error", f"{path}.description", "description must be at least 20 characters")
            description = ""
        lint_json_schema(tool.get("inputSchema"), f"{path}.inputSchema", issues, require_object_root=True)
        lint_json_schema(tool.get("outputSchema"), f"{path}.outputSchema", issues, require_object_root=False)
        lint_error_schemas(tool.get("errorSchemas"), f"{path}.errorSchemas", issues)
        effects = lint_string_set(tool.get("effects"), f"{path}.effects", EFFECTS, issues)
        lint_string_set(tool.get("dataClasses"), f"{path}.dataClasses", DATA_CLASSES, issues)
        auth_mode = lint_authorization(tool.get("authorization"), f"{path}.authorization", issues)
        if not isinstance(tool.get("idempotent"), bool):
            add(issues, "error", f"{path}.idempotent", "idempotent must be boolean")
        if auth_mode == "public" and effects - {"none", "read"}:
            add(issues, "warning", f"{path}.authorization.mode", "public tool declares a consequential effect; verify intent")
        for pattern, expected_effects, label in DANGEROUS_DESCRIPTION_SIGNALS:
            if description and pattern.search(description) and not (effects & expected_effects):
                add(
                    issues,
                    "warning",
                    f"{path}.effects",
                    f"description suggests {label} but effects omits {sorted(expected_effects)[0]!r}",
                )
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Structurally lint an MCP design manifest; this is not a safety certification"
    )
    parser.add_argument("manifest", type=Path, help="JSON manifest path")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read valid JSON: {exc}", file=sys.stderr)
        return 2
    issues = lint_manifest(data)
    errors = sum(item["level"] == "error" for item in issues)
    warnings = sum(item["level"] == "warning" for item in issues)
    result = {
        "structural_status": "fail" if errors else "pass",
        "errors": errors,
        "warnings": warnings,
        "issues": issues,
        "assurance": "none; run protocol, authorization, and adversarial tests",
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in issues:
            print(f"{item['level'].upper()}: {item['path']}: {item['message']}")
        print(f"Structural manifest status: {result['structural_status'].upper()}")
        print(f"Summary: {errors} error(s), {warnings} warning(s)")
        print("This lint result is not protocol conformance or safety certification.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
