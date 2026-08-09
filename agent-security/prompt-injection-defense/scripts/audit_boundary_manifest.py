#!/usr/bin/env python3
"""Structurally lint a prompt-injection trust-boundary manifest.

The manifest records control claims and gaps. Passing lint does not mean the
controls are implemented or effective; only evidence-backed tests can do that.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
TRUST = {"trusted", "mixed", "untrusted"}
CLASSIFICATIONS = {
    "public",
    "internal",
    "confidential",
    "restricted",
    "personal",
    "financial",
    "health",
    "credentials",
}
EFFECTS = {
    "read",
    "write",
    "delete",
    "execute",
    "external",
    "financial",
    "access-control",
    "network-egress",
}
RISKS = {"low", "medium", "high", "critical"}
CONFIRMATION = {"none", "risk-based", "always"}
CONTROL_STATUS = {"missing", "planned", "implemented", "verified"}
SINK_TYPES = {"ui", "api", "file", "database", "message", "code-execution", "agent", "log", "other"}


def add(items: list[dict[str, str]], level: str, path: str, message: str) -> None:
    items.append({"level": level, "path": path, "message": message})


def string_array(
    value: Any,
    path: str,
    items: list[dict[str, str]],
    *,
    nonempty: bool = False,
) -> set[str]:
    if not isinstance(value, list) or (nonempty and not value) or any(
        not isinstance(entry, str) or not entry.strip() for entry in value
    ):
        qualifier = "non-empty " if nonempty else ""
        add(items, "error", path, f"must be a {qualifier}array of non-empty strings")
        return set()
    values = set(value)
    if len(values) != len(value):
        add(items, "error", path, "values must be unique")
    return values


def identifier(value: Any, path: str, items: list[dict[str, str]]) -> str | None:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        add(items, "error", path, "must use 1-128 safe identifier characters")
        return None
    return value


def text(value: Any, path: str, items: list[dict[str, str]]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        add(items, "error", path, "must be a non-empty string")
        return None
    return value


def timestamp(value: Any, path: str, items: list[dict[str, str]]) -> datetime | None:
    if not isinstance(value, str):
        add(items, "error", path, "must be an ISO 8601 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        add(items, "error", path, "must be a valid ISO 8601 timestamp")
        return None
    if parsed.tzinfo is None:
        add(items, "error", path, "timestamp must include a timezone")
        return None
    return parsed


def unique_object_ids(value: Any, path: str, items: list[dict[str, str]], *, nonempty: bool) -> set[str]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "non-empty " if nonempty else ""
        add(items, "error", path, f"must be a {qualifier}array")
        return set()
    seen: set[str] = set()
    for index, entry in enumerate(value):
        entry_path = f"{path}[{index}]"
        if not isinstance(entry, dict):
            add(items, "error", entry_path, "must be an object")
            continue
        entry_id = identifier(entry.get("id"), f"{entry_path}.id", items)
        if entry_id in seen:
            add(items, "error", f"{entry_path}.id", f"duplicate id {entry_id!r}")
        elif entry_id:
            seen.add(entry_id)
    return seen


def validate_controls(value: Any, items: list[dict[str, str]]) -> set[str]:
    ids = unique_object_ids(value, "$.controls", items, nonempty=True)
    if not isinstance(value, list):
        return ids
    now = datetime.now(timezone.utc)
    for index, control in enumerate(value):
        path = f"$.controls[{index}]"
        if not isinstance(control, dict):
            continue
        text(control.get("kind"), f"{path}.kind", items)
        status = control.get("status")
        if status not in CONTROL_STATUS:
            add(items, "error", f"{path}.status", f"must be one of {sorted(CONTROL_STATUS)}")
        text(control.get("enforcement_point"), f"{path}.enforcement_point", items)
        text(control.get("owner"), f"{path}.owner", items)
        evidence = string_array(control.get("evidence_ids"), f"{path}.evidence_ids", items)
        tests = string_array(control.get("test_ids"), f"{path}.test_ids", items)
        if status == "implemented" and not evidence:
            add(items, "warning", f"{path}.evidence_ids", "implemented control has no implementation evidence")
        if status == "verified":
            if not evidence:
                add(items, "error", f"{path}.evidence_ids", "verified control requires evidence IDs")
            if not tests:
                add(items, "error", f"{path}.test_ids", "verified control requires test IDs")
        if status in {"missing", "planned"} and (evidence or tests):
            add(items, "warning", path, f"{status} control includes evidence/test IDs; verify status")
        time_limited = control.get("time_limited")
        if not isinstance(time_limited, bool):
            add(items, "error", f"{path}.time_limited", "must be boolean")
        expiry_value = control.get("expires_at")
        if time_limited:
            expiry = timestamp(expiry_value, f"{path}.expires_at", items)
            if expiry and expiry <= now and status == "verified":
                add(items, "error", f"{path}.expires_at", "verified time-limited control is expired")
        elif expiry_value is not None:
            add(items, "error", f"{path}.expires_at", "must be null when time_limited is false")
    return ids


def validate_control_refs(
    value: Any,
    path: str,
    items: list[dict[str, str]],
    control_ids: set[str],
    *,
    nonempty: bool = False,
) -> set[str]:
    refs = string_array(value, path, items, nonempty=nonempty)
    unknown = sorted(refs - control_ids)
    if unknown:
        add(items, "error", path, f"unknown control IDs: {', '.join(unknown)}")
    return refs


def validate(data: Any) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if not isinstance(data, dict):
        return [{"level": "error", "path": "$", "message": "manifest must be a JSON object"}]
    text(data.get("system"), "$.system", items)
    control_ids = validate_controls(data.get("controls"), items)

    assets = data.get("protected_assets")
    unique_object_ids(assets, "$.protected_assets", items, nonempty=True)
    if isinstance(assets, list):
        for index, asset in enumerate(assets):
            path = f"$.protected_assets[{index}]"
            if not isinstance(asset, dict):
                continue
            if asset.get("classification") not in CLASSIFICATIONS:
                add(items, "error", f"{path}.classification", f"must be one of {sorted(CLASSIFICATIONS)}")
            text(asset.get("owner"), f"{path}.owner", items)

    sources = data.get("data_sources")
    unique_object_ids(sources, "$.data_sources", items, nonempty=True)
    if isinstance(sources, list):
        for index, source in enumerate(sources):
            path = f"$.data_sources[{index}]"
            if not isinstance(source, dict):
                continue
            trust = source.get("trust")
            if trust not in TRUST:
                add(items, "error", f"{path}.trust", f"must be one of {sorted(TRUST)}")
            string_array(source.get("modalities"), f"{path}.modalities", items, nonempty=True)
            refs = validate_control_refs(
                source.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=trust in {"mixed", "untrusted"}
            )
            if trust in {"mixed", "untrusted"} and not refs:
                add(items, "warning", f"{path}.control_ids", "untrusted path has no placed control")

    sinks = data.get("sinks")
    sink_ids = unique_object_ids(sinks, "$.sinks", items, nonempty=True)
    if isinstance(sinks, list):
        for index, sink in enumerate(sinks):
            path = f"$.sinks[{index}]"
            if not isinstance(sink, dict):
                continue
            if sink.get("type") not in SINK_TYPES:
                add(items, "error", f"{path}.type", f"must be one of {sorted(SINK_TYPES)}")
            if sink.get("trust") not in TRUST:
                add(items, "error", f"{path}.trust", f"must be one of {sorted(TRUST)}")
            text(sink.get("owner"), f"{path}.owner", items)
            validate_control_refs(sink.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=True)

    destinations = data.get("destinations")
    destination_ids = unique_object_ids(destinations, "$.destinations", items, nonempty=False)
    if isinstance(destinations, list):
        for index, destination in enumerate(destinations):
            path = f"$.destinations[{index}]"
            if not isinstance(destination, dict):
                continue
            text(destination.get("kind"), f"{path}.kind", items)
            text(destination.get("owner"), f"{path}.owner", items)
            validate_control_refs(destination.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=True)

    memory = data.get("memory_stores")
    unique_object_ids(memory, "$.memory_stores", items, nonempty=False)
    if isinstance(memory, list):
        for index, store in enumerate(memory):
            path = f"$.memory_stores[{index}]"
            if not isinstance(store, dict):
                continue
            if store.get("trust") not in TRUST:
                add(items, "error", f"{path}.trust", f"must be one of {sorted(TRUST)}")
            string_array(store.get("read_principals"), f"{path}.read_principals", items, nonempty=True)
            string_array(store.get("write_principals"), f"{path}.write_principals", items, nonempty=True)
            validate_control_refs(store.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=True)

    hops = data.get("agent_hops")
    unique_object_ids(hops, "$.agent_hops", items, nonempty=False)
    if isinstance(hops, list):
        for index, hop in enumerate(hops):
            path = f"$.agent_hops[{index}]"
            if not isinstance(hop, dict):
                continue
            text(hop.get("from_agent"), f"{path}.from_agent", items)
            text(hop.get("to_agent"), f"{path}.to_agent", items)
            validate_control_refs(hop.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=True)

    credentials = data.get("credential_boundaries")
    unique_object_ids(credentials, "$.credential_boundaries", items, nonempty=False)
    if isinstance(credentials, list):
        for index, boundary in enumerate(credentials):
            path = f"$.credential_boundaries[{index}]"
            if not isinstance(boundary, dict):
                continue
            for field in ("credential_class", "holder", "audience", "storage"):
                text(boundary.get(field), f"{path}.{field}", items)
            passthrough = boundary.get("downstream_passthrough")
            if not isinstance(passthrough, bool):
                add(items, "error", f"{path}.downstream_passthrough", "must be boolean")
            elif passthrough:
                add(items, "error", f"{path}.downstream_passthrough", "credential passthrough must not cross this boundary")
            validate_control_refs(boundary.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=True)

    tools = data.get("tools")
    unique_object_ids(tools, "$.tools", items, nonempty=False)
    external_tool = False
    if isinstance(tools, list):
        for index, tool in enumerate(tools):
            path = f"$.tools[{index}]"
            if not isinstance(tool, dict):
                continue
            effects = string_array(tool.get("effects"), f"{path}.effects", items, nonempty=True)
            unknown_effects = sorted(effects - EFFECTS)
            if unknown_effects:
                add(items, "error", f"{path}.effects", f"unsupported effects: {', '.join(unknown_effects)}")
            if effects & {"external", "network-egress"}:
                external_tool = True
            risk = tool.get("risk")
            if risk not in RISKS:
                add(items, "error", f"{path}.risk", f"must be one of {sorted(RISKS)}")
            destination_refs = string_array(tool.get("destination_ids"), f"{path}.destination_ids", items)
            unknown_destinations = sorted(destination_refs - destination_ids)
            if unknown_destinations:
                add(items, "error", f"{path}.destination_ids", f"unknown destinations: {', '.join(unknown_destinations)}")
            sink_refs = string_array(tool.get("sink_ids"), f"{path}.sink_ids", items, nonempty=True)
            unknown_sinks = sorted(sink_refs - sink_ids)
            if unknown_sinks:
                add(items, "error", f"{path}.sink_ids", f"unknown sinks: {', '.join(unknown_sinks)}")
            validate_control_refs(tool.get("control_ids"), f"{path}.control_ids", items, control_ids, nonempty=True)
            confirmation = tool.get("confirmation")
            if not isinstance(confirmation, dict):
                add(items, "error", f"{path}.confirmation", "must be a structured object")
                mode = None
            else:
                mode = confirmation.get("mode")
                if mode not in CONFIRMATION:
                    add(items, "error", f"{path}.confirmation.mode", f"must be one of {sorted(CONFIRMATION)}")
                text(confirmation.get("enforcement_point"), f"{path}.confirmation.enforcement_point", items)
                text(confirmation.get("owner"), f"{path}.confirmation.owner", items)
            if risk == "critical" and mode == "none":
                add(items, "error", f"{path}.confirmation.mode", "critical tool must have risk-based or always confirmation")
            elif risk == "high" and mode == "none":
                add(items, "warning", f"{path}.confirmation.mode", "high-risk tool has no confirmation")
            if effects & {"delete", "execute", "external", "financial", "access-control"} and mode == "none":
                add(items, "warning", f"{path}.confirmation.mode", "consequential tool has no confirmation")
    if external_tool and not destination_ids:
        add(items, "error", "$.destinations", "external or egress tools require explicit destinations")

    for required_field in ("memory_stores", "agent_hops", "destinations", "credential_boundaries"):
        if required_field not in data:
            add(items, "error", f"$.{required_field}", "field is required; use an empty array when not applicable")
    return items


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Structurally lint a prompt-injection boundary manifest; not a security certification"
    )
    parser.add_argument("manifest", type=Path, help="boundary manifest JSON path")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read valid JSON: {exc}", file=sys.stderr)
        return 2
    items = validate(data)
    errors = sum(item["level"] == "error" for item in items)
    warnings = sum(item["level"] == "warning" for item in items)
    result = {
        "structural_status": "fail" if errors else "pass",
        "errors": errors,
        "warnings": warnings,
        "issues": items,
        "assurance": "none; verify implementation and adversarial-test evidence separately",
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in items:
            print(f"{item['level'].upper()}: {item['path']}: {item['message']}")
        print(f"Structural manifest status: {result['structural_status'].upper()}")
        print(f"Summary: {errors} error(s), {warnings} warning(s)")
        print("This lint result is not evidence that controls are implemented or effective.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
