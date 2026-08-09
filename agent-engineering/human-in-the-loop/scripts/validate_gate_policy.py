#!/usr/bin/env python3
"""Strictly validate an approval-gate policy JSON file."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
ACTION_PATTERN_RE = re.compile(r"^[a-z0-9*?][a-z0-9.*?_-]{0,127}$")
FIELD_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
RISK_TIERS = {"low", "medium", "high", "critical"}
TIMEOUT_ACTIONS = {"deny", "cancel", "escalate"}
PREDICATE_OPS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not-in", "exists", "matches"}
WAIVER_TYPES = {"critical-single-control", "self-approval"}
INVALIDATION_EVENTS = {
    "role-change",
    "policy-change",
    "proposal-change",
    "target-state-change",
    "expiry",
}
REQUIRED_LOG_FIELDS = {
    "event_id",
    "proposal_id",
    "proposal_digest",
    "policy_version",
    "requester_subject",
    "approver_subject",
    "approver_role",
    "decision",
    "decided_at",
    "escalation_event",
    "execution_authorization_decision",
    "audit_outage_state",
    "compensation_state",
    "break_glass_event",
}
VALIDATION_SCOPE = (
    "Structural policy validation only. A passing result does not certify authorization design, "
    "human judgment quality, runtime enforcement, audit integrity, regulatory compliance, or safety."
)


def issue(items: list[dict[str, str]], level: str, path: str, message: str) -> None:
    items.append({"level": level, "path": path, "message": message})


def parse_timestamp(value: Any, path: str, items: list[dict[str, str]]) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        issue(items, "error", path, "must be a non-empty ISO 8601 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        issue(items, "error", path, "must be a valid ISO 8601 timestamp")
        return None
    if parsed.tzinfo is None:
        issue(items, "error", path, "timestamp must include a timezone")
        return None
    return parsed


def validate_string_array(
    value: Any,
    path: str,
    items: list[dict[str, str]],
    *,
    nonempty: bool = True,
) -> set[str]:
    if not isinstance(value, list) or (nonempty and not value) or any(
        not isinstance(entry, str) or not entry.strip() for entry in value
    ):
        qualifier = "non-empty " if nonempty else ""
        issue(items, "error", path, f"must be a {qualifier}array of non-empty strings")
        return set()
    result = set(value)
    if len(result) != len(value):
        issue(items, "error", path, "values must be unique")
    return result


def validate_predicate(value: Any, path: str, items: list[dict[str, str]], depth: int = 0) -> None:
    if depth > 8:
        issue(items, "error", path, "predicate nesting exceeds 8 levels")
        return
    if not isinstance(value, dict) or not value:
        issue(items, "error", path, "predicate must be a non-empty object")
        return
    logical = [key for key in ("all", "any", "not") if key in value]
    leaf_keys = {"field", "op", "value"} & set(value)
    if logical and leaf_keys:
        issue(items, "error", path, "predicate cannot mix logical and leaf forms")
        return
    if logical:
        if len(logical) != 1 or set(value) != {logical[0]}:
            issue(items, "error", path, "logical predicate must contain exactly one of all, any, or not")
            return
        operator = logical[0]
        child = value[operator]
        if operator in {"all", "any"}:
            if not isinstance(child, list) or not child:
                issue(items, "error", f"{path}.{operator}", "must be a non-empty predicate array")
                return
            for index, nested in enumerate(child):
                validate_predicate(nested, f"{path}.{operator}[{index}]", items, depth + 1)
        else:
            validate_predicate(child, f"{path}.not", items, depth + 1)
        return
    if set(value) != {"field", "op", "value"}:
        issue(items, "error", path, "leaf predicate requires exactly field, op, and value")
        return
    field = value.get("field")
    op = value.get("op")
    operand = value.get("value")
    if not isinstance(field, str) or not FIELD_RE.fullmatch(field):
        issue(items, "error", f"{path}.field", "field must be a bounded dotted identifier")
    if op not in PREDICATE_OPS:
        issue(items, "error", f"{path}.op", f"op must be one of {sorted(PREDICATE_OPS)}")
        return
    if op in {"in", "not-in"} and (not isinstance(operand, list) or not operand):
        issue(items, "error", f"{path}.value", f"{op} requires a non-empty array")
    elif op == "exists" and not isinstance(operand, bool):
        issue(items, "error", f"{path}.value", "exists requires a boolean")
    elif op in {"gt", "gte", "lt", "lte"} and (
        not isinstance(operand, (int, float)) or isinstance(operand, bool)
    ):
        issue(items, "error", f"{path}.value", f"{op} requires a number")
    elif op == "matches":
        if not isinstance(operand, str) or not operand or len(operand) > 256:
            issue(items, "error", f"{path}.value", "matches requires a non-empty pattern up to 256 characters")
        else:
            try:
                re.compile(operand)
            except re.error as exc:
                issue(items, "error", f"{path}.value", f"invalid regular expression: {exc}")


def validate_behavior(
    gate: dict[str, Any],
    path: str,
    items: list[dict[str, str]],
    roles: set[str],
    subjects: set[str],
) -> None:
    escalation = gate.get("escalation")
    if not isinstance(escalation, dict):
        issue(items, "error", f"{path}.escalation", "must be a structured object")
    else:
        after = escalation.get("after_seconds")
        if not isinstance(after, int) or isinstance(after, bool) or not 30 <= after <= 604800:
            issue(items, "error", f"{path}.escalation.after_seconds", "must be 30 to 604800")
        escalation_roles = validate_string_array(
            escalation.get("to_roles"), f"{path}.escalation.to_roles", items
        )
        unknown = sorted(escalation_roles - roles)
        if unknown:
            issue(items, "error", f"{path}.escalation.to_roles", f"unknown roles: {', '.join(unknown)}")
        attempts = escalation.get("max_attempts")
        if not isinstance(attempts, int) or isinstance(attempts, bool) or not 1 <= attempts <= 20:
            issue(items, "error", f"{path}.escalation.max_attempts", "must be 1 to 20")
        if escalation.get("on_exhausted") not in {"deny", "cancel", "block"}:
            issue(items, "error", f"{path}.escalation.on_exhausted", "must be deny, cancel, or block")

    outage = gate.get("audit_outage")
    if not isinstance(outage, dict):
        issue(items, "error", f"{path}.audit_outage", "must be a structured object")
    else:
        behavior = outage.get("behavior")
        if behavior not in {"fail-closed", "buffer-signed"}:
            issue(items, "error", f"{path}.audit_outage.behavior", "must be fail-closed or buffer-signed")
        notify = validate_string_array(outage.get("notify_subjects"), f"{path}.audit_outage.notify_subjects", items)
        unknown = sorted(notify - subjects)
        if unknown:
            issue(items, "error", f"{path}.audit_outage.notify_subjects", f"unknown subjects: {', '.join(unknown)}")
        if behavior == "buffer-signed":
            duration = outage.get("max_buffer_seconds")
            if not isinstance(duration, int) or isinstance(duration, bool) or not 1 <= duration <= 3600:
                issue(items, "error", f"{path}.audit_outage.max_buffer_seconds", "must be 1 to 3600")
            if gate.get("risk_tier") == "critical":
                issue(items, "error", f"{path}.audit_outage.behavior", "critical gates must fail closed on audit outage")

    reauth = gate.get("reauthorization")
    if not isinstance(reauth, dict):
        issue(items, "error", f"{path}.reauthorization", "must be a structured object")
    else:
        if reauth.get("required_at_execution") is not True:
            issue(items, "error", f"{path}.reauthorization.required_at_execution", "must be true")
        events = validate_string_array(
            reauth.get("invalidation_events"), f"{path}.reauthorization.invalidation_events", items
        )
        unknown = sorted(events - INVALIDATION_EVENTS)
        if unknown:
            issue(items, "error", f"{path}.reauthorization.invalidation_events", f"unknown events: {', '.join(unknown)}")
        missing = sorted({"proposal-change", "policy-change", "expiry"} - events)
        if missing:
            issue(items, "error", f"{path}.reauthorization.invalidation_events", f"missing required events: {', '.join(missing)}")

    compensation = gate.get("compensation")
    if not isinstance(compensation, dict):
        issue(items, "error", f"{path}.compensation", "must be a structured object")
    else:
        mode = compensation.get("mode")
        if mode not in {"automatic", "manual", "required-but-unavailable", "not-applicable"}:
            issue(items, "error", f"{path}.compensation.mode", "unsupported compensation mode")
        owner = compensation.get("owner_subject")
        if owner not in subjects:
            issue(items, "error", f"{path}.compensation.owner_subject", "must name a known subject")
        reference = compensation.get("procedure_reference")
        if not isinstance(reference, str) or not reference.strip():
            issue(items, "error", f"{path}.compensation.procedure_reference", "must be non-empty")
        if mode in {"required-but-unavailable", "not-applicable"}:
            rationale = compensation.get("rationale")
            if not isinstance(rationale, str) or len(rationale.strip()) < 20:
                issue(items, "error", f"{path}.compensation.rationale", "must document the limitation")

    break_glass = gate.get("break_glass")
    if not isinstance(break_glass, dict) or not isinstance(break_glass.get("enabled"), bool):
        issue(items, "error", f"{path}.break_glass", "must be an object with boolean enabled")
    elif break_glass["enabled"]:
        approvers = validate_string_array(
            break_glass.get("approver_subjects"), f"{path}.break_glass.approver_subjects", items
        )
        unknown = sorted(approvers - subjects)
        if unknown:
            issue(items, "error", f"{path}.break_glass.approver_subjects", f"unknown subjects: {', '.join(unknown)}")
        if len(approvers) < 2:
            issue(items, "error", f"{path}.break_glass.approver_subjects", "requires at least two distinct subjects")
        for field in ("scope", "procedure_reference"):
            if not isinstance(break_glass.get(field), str) or not break_glass[field].strip():
                issue(items, "error", f"{path}.break_glass.{field}", "must be non-empty")
        duration = break_glass.get("expires_in_seconds")
        if not isinstance(duration, int) or isinstance(duration, bool) or not 60 <= duration <= 3600:
            issue(items, "error", f"{path}.break_glass.expires_in_seconds", "must be 60 to 3600")
        for field in ("reason_required", "notify_immediately", "after_action_review"):
            if break_glass.get(field) is not True:
                issue(items, "error", f"{path}.break_glass.{field}", "must be true when break-glass is enabled")


def validate_waivers(
    value: Any,
    owner_subject: str | None,
    items: list[dict[str, str]],
) -> dict[tuple[str, str], str]:
    if not isinstance(value, list):
        issue(items, "error", "$.waivers", "waivers must be an array")
        return {}
    valid: dict[tuple[str, str], str] = {}
    seen: set[str] = set()
    now = datetime.now(timezone.utc)
    for index, waiver in enumerate(value):
        path = f"$.waivers[{index}]"
        if not isinstance(waiver, dict):
            issue(items, "error", path, "waiver must be an object")
            continue
        waiver_id = waiver.get("id")
        gate_id = waiver.get("gate_id")
        waiver_type = waiver.get("type")
        if not isinstance(waiver_id, str) or not ID_RE.fullmatch(waiver_id):
            issue(items, "error", f"{path}.id", "must be a safe identifier")
        elif waiver_id in seen:
            issue(items, "error", f"{path}.id", "waiver IDs must be unique")
        else:
            seen.add(waiver_id)
        if not isinstance(gate_id, str) or not ID_RE.fullmatch(gate_id):
            issue(items, "error", f"{path}.gate_id", "must name a valid gate")
        if waiver_type not in WAIVER_TYPES:
            issue(items, "error", f"{path}.type", f"must be one of {sorted(WAIVER_TYPES)}")
        if waiver.get("owner_subject") != owner_subject:
            issue(items, "error", f"{path}.owner_subject", "must equal the policy owner subject")
        for field in ("approval_reference", "rationale"):
            minimum = 20 if field == "rationale" else 1
            if not isinstance(waiver.get(field), str) or len(waiver[field].strip()) < minimum:
                issue(items, "error", f"{path}.{field}", f"must contain at least {minimum} character(s)")
        controls = validate_string_array(
            waiver.get("compensating_controls"), f"{path}.compensating_controls", items
        )
        approved = parse_timestamp(waiver.get("approved_at"), f"{path}.approved_at", items)
        expires = parse_timestamp(waiver.get("expires_at"), f"{path}.expires_at", items)
        if approved and expires and expires <= approved:
            issue(items, "error", f"{path}.expires_at", "must be later than approved_at")
        if expires and expires <= now:
            issue(items, "error", f"{path}.expires_at", "waiver is expired")
        if (
            isinstance(waiver_id, str)
            and isinstance(gate_id, str)
            and waiver_type in WAIVER_TYPES
            and controls
            and approved
            and expires
            and expires > now
            and waiver.get("owner_subject") == owner_subject
        ):
            valid[(gate_id, waiver_type)] = waiver_id
    return valid


def validate(data: Any) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if not isinstance(data, dict):
        return [{"level": "error", "path": "$", "message": "policy must be a JSON object"}]
    for field in ("workflow", "policy_version", "policy_owner_subject", "policy_approval_reference"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            issue(items, "error", f"$.{field}", f"{field} must be a non-empty string")
    owner_subject = data.get("policy_owner_subject") if isinstance(data.get("policy_owner_subject"), str) else None
    if data.get("default") != "deny":
        issue(items, "error", "$.default", "default must be deny")

    roles = validate_string_array(data.get("roles"), "$.roles", items)
    subjects_value = data.get("approver_subjects")
    subjects: set[str] = set()
    subjects_by_role: dict[str, set[str]] = {role: set() for role in roles}
    if not isinstance(subjects_value, list) or not subjects_value:
        issue(items, "error", "$.approver_subjects", "must be a non-empty array")
    else:
        for index, subject in enumerate(subjects_value):
            path = f"$.approver_subjects[{index}]"
            if not isinstance(subject, dict):
                issue(items, "error", path, "subject must be an object")
                continue
            subject_id = subject.get("subject_id")
            if not isinstance(subject_id, str) or not ID_RE.fullmatch(subject_id):
                issue(items, "error", f"{path}.subject_id", "must be a stable safe identifier")
                continue
            if subject_id in subjects:
                issue(items, "error", f"{path}.subject_id", "subject IDs must be unique")
            subjects.add(subject_id)
            subject_roles = validate_string_array(subject.get("roles"), f"{path}.roles", items)
            unknown = sorted(subject_roles - roles)
            if unknown:
                issue(items, "error", f"{path}.roles", f"unknown roles: {', '.join(unknown)}")
            for role in subject_roles & roles:
                subjects_by_role.setdefault(role, set()).add(subject_id)
    if owner_subject and owner_subject not in subjects:
        issue(items, "error", "$.policy_owner_subject", "must name a subject in approver_subjects")

    log_fields = validate_string_array(data.get("decision_log_fields"), "$.decision_log_fields", items)
    missing_log = sorted(REQUIRED_LOG_FIELDS - log_fields)
    if missing_log:
        issue(items, "error", "$.decision_log_fields", f"missing required fields: {', '.join(missing_log)}")
    valid_waivers = validate_waivers(data.get("waivers"), owner_subject, items)

    gates = data.get("gates")
    if not isinstance(gates, list) or not gates:
        issue(items, "error", "$.gates", "gates must be a non-empty array")
        return items
    seen: set[str] = set()
    patterns: set[str] = set()
    for index, gate in enumerate(gates):
        path = f"$.gates[{index}]"
        if not isinstance(gate, dict):
            issue(items, "error", path, "gate must be an object")
            continue
        gate_id = gate.get("id")
        if not isinstance(gate_id, str) or not ID_RE.fullmatch(gate_id):
            issue(items, "error", f"{path}.id", "id must be a safe identifier")
        elif gate_id in seen:
            issue(items, "error", f"{path}.id", f"duplicate gate id {gate_id!r}")
        else:
            seen.add(gate_id)
        pattern = gate.get("action_pattern")
        if not isinstance(pattern, str) or not ACTION_PATTERN_RE.fullmatch(pattern):
            issue(items, "error", f"{path}.action_pattern", "must be a bounded action glob")
        elif pattern in patterns:
            issue(items, "warning", f"{path}.action_pattern", "duplicate pattern may make precedence ambiguous")
        else:
            patterns.add(pattern)
        risk = gate.get("risk_tier")
        if risk not in RISK_TIERS:
            issue(items, "error", f"{path}.risk_tier", f"must be one of {sorted(RISK_TIERS)}")
        validate_predicate(gate.get("when"), f"{path}.when", items)
        approver_roles = validate_string_array(
            gate.get("required_approver_roles"), f"{path}.required_approver_roles", items
        )
        unknown_roles = sorted(approver_roles - roles)
        if unknown_roles:
            issue(items, "error", f"{path}.required_approver_roles", f"unknown roles: {', '.join(unknown_roles)}")
        eligible_subjects = set().union(*(subjects_by_role.get(role, set()) for role in approver_roles))
        quorum = gate.get("quorum")
        distinct = gate.get("minimum_distinct_subjects")
        if not isinstance(quorum, int) or isinstance(quorum, bool) or quorum < 1:
            issue(items, "error", f"{path}.quorum", "must be a positive integer")
        if not isinstance(distinct, int) or isinstance(distinct, bool) or distinct < 1:
            issue(items, "error", f"{path}.minimum_distinct_subjects", "must be a positive integer")
        elif distinct > len(eligible_subjects):
            issue(items, "error", f"{path}.minimum_distinct_subjects", "exceeds eligible distinct approver subjects")
        if isinstance(quorum, int) and isinstance(distinct, int) and quorum < distinct:
            issue(items, "error", f"{path}.quorum", "must be at least minimum_distinct_subjects")
        requester_may_approve = gate.get("requester_may_approve")
        if not isinstance(requester_may_approve, bool):
            issue(items, "error", f"{path}.requester_may_approve", "must be boolean")
        waiver_ids = validate_string_array(gate.get("waiver_ids", []), f"{path}.waiver_ids", items, nonempty=False)
        if risk == "critical" and (
            not isinstance(quorum, int)
            or quorum < 2
            or not isinstance(distinct, int)
            or distinct < 2
        ):
            waiver_id = valid_waivers.get((gate_id, "critical-single-control")) if isinstance(gate_id, str) else None
            if not waiver_id or waiver_id not in waiver_ids:
                issue(items, "error", f"{path}.quorum", "critical single-control requires an active owner-approved waiver")
        if requester_may_approve:
            waiver_id = valid_waivers.get((gate_id, "self-approval")) if isinstance(gate_id, str) else None
            if not waiver_id or waiver_id not in waiver_ids:
                issue(items, "error", f"{path}.requester_may_approve", "self-approval requires an active owner-approved waiver")
        evidence = validate_string_array(gate.get("evidence"), f"{path}.evidence", items)
        missing_evidence = sorted({"proposal_digest", "target", "normalized_parameters"} - evidence)
        if missing_evidence:
            issue(items, "error", f"{path}.evidence", f"missing required evidence: {', '.join(missing_evidence)}")
        expiry = gate.get("expires_in_seconds")
        if not isinstance(expiry, int) or isinstance(expiry, bool) or not 30 <= expiry <= 604800:
            issue(items, "error", f"{path}.expires_in_seconds", "must be 30 to 604800 seconds")
        if gate.get("on_timeout") not in TIMEOUT_ACTIONS:
            issue(items, "error", f"{path}.on_timeout", f"must be one of {sorted(TIMEOUT_ACTIONS)}")
        validate_behavior(gate, path, items, roles, subjects)
    known_gate_ids = seen
    for (waiver_gate, _waiver_type), _waiver_id in valid_waivers.items():
        if waiver_gate not in known_gate_ids:
            issue(items, "error", "$.waivers", f"waiver references unknown gate {waiver_gate!r}")
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="Strictly validate an approval-gate policy")
    parser.add_argument("policy", type=Path, help="policy JSON path")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    try:
        data = json.loads(args.policy.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read valid JSON: {exc}", file=sys.stderr)
        return 2
    items = validate(data)
    errors = sum(item["level"] == "error" for item in items)
    warnings = sum(item["level"] == "warning" for item in items)
    if args.json:
        print(
            json.dumps(
                {
                    "structurally_valid": errors == 0,
                    "validation_scope": VALIDATION_SCOPE,
                    "errors": errors,
                    "warnings": warnings,
                    "issues": items,
                },
                indent=2,
            )
        )
    else:
        for item in items:
            print(f"{item['level'].upper()}: {item['path']}: {item['message']}")
        print(f"Summary: {errors} error(s), {warnings} warning(s)")
        print(f"Scope: {VALIDATION_SCOPE}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
