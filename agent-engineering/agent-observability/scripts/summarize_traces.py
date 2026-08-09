#!/usr/bin/env python3
"""Validate JSONL span structure and emit content-free trace health metrics."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import sys
import tempfile
from collections import Counter, defaultdict, deque
from pathlib import Path
from statistics import fmean
from typing import Any


VALID_STATUSES = {"ok", "error", "unset"}
SECRET_KEY_PATTERN = re.compile(
    r"(?:^|_)(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"authorization|cookie|private[_-]?key|credential|client[_-]?secret)(?:$|_)",
    re.IGNORECASE,
)
CONTENT_KEYS = {
    "body",
    "content",
    "email",
    "input_text",
    "message",
    "messages",
    "output_text",
    "phone",
    "prompt",
    "request_body",
    "response",
    "response_body",
    "ssn",
}
SECRET_VALUE_PATTERNS = (
    (re.compile(r"^\s*bearer\s+\S+", re.IGNORECASE), "bearer-like value"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key-like value"),
    (re.compile(r"^(?:sk|pk)_[A-Za-z0-9_-]{16,}$"), "credential-like value"),
)


def validate_output_target(input_path: Path, output_path: Path) -> None:
    """Reject output targets that could replace the input or are not regular files."""
    input_lexical = Path(os.path.abspath(os.fspath(input_path)))
    output_lexical = Path(os.path.abspath(os.fspath(output_path)))
    if output_lexical == input_lexical:
        raise ValueError("--output must not be the input file")

    try:
        input_resolved = input_path.resolve(strict=True)
        output_resolved = output_path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot resolve --output safely: {exc}") from exc
    if output_resolved == input_resolved:
        raise ValueError("--output must not resolve to the input file")

    try:
        output_stat = output_path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(output_stat.st_mode):
        raise ValueError("--output must not be a symbolic link")
    if not stat.S_ISREG(output_stat.st_mode):
        raise ValueError("--output must be a regular file or a new path")
    if os.path.samefile(input_path, output_path):
        raise ValueError("--output must not be a hard link to the input file")


def write_text_atomic(input_path: Path, output_path: Path, payload: str) -> None:
    """Write beside the destination and atomically replace it after safety checks."""
    validate_output_target(input_path, output_path)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        # Recheck immediately before replacement in case the destination changed
        # while the temporary file was being written.
        validate_output_target(input_path, output_path)
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def finite_number(value: Any, field: str, line_number: int) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"line {line_number}: {field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"line {line_number}: {field} must be finite")
    return result


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def required_text(record: dict[str, Any], field: str, line_number: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"line {line_number}: {field} must be a non-empty string")
    return value.strip()


def safe_path_segment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "?", value)[:80] or "?"


def sensitive_findings(
    value: Any,
    *,
    trace_id: str,
    span_id: str,
    path: str = "$",
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key)
            child_path = f"{path}.{safe_path_segment(key)}"
            normalized_key = key.casefold().replace("-", "_")
            if SECRET_KEY_PATTERN.search(normalized_key):
                findings.append(
                    {
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "field_path": child_path,
                        "reason": "secret- or credential-bearing field name",
                    }
                )
            elif normalized_key in CONTENT_KEYS:
                findings.append(
                    {
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "field_path": child_path,
                        "reason": "content- or personal-data-bearing field name",
                    }
                )
            findings.extend(
                sensitive_findings(child, trace_id=trace_id, span_id=span_id, path=child_path)
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(
                sensitive_findings(
                    child,
                    trace_id=trace_id,
                    span_id=span_id,
                    path=f"{path}[{index}]",
                )
            )
    elif isinstance(value, str):
        for pattern, reason in SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                findings.append(
                    {
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "field_path": path,
                        "reason": reason,
                    }
                )
                break
    return findings


def load_spans(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    spans: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            try:
                source = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(source, dict):
                raise ValueError(f"line {line_number}: span must be an object")

            trace_id = required_text(source, "trace_id", line_number)
            span_id = required_text(source, "span_id", line_number)
            name = required_text(source, "name", line_number)
            key = (trace_id, span_id)
            if key in seen:
                raise ValueError(f"line {line_number}: duplicate span_id {span_id!r} in trace {trace_id!r}")
            seen.add(key)

            status = source.get("status")
            if status not in VALID_STATUSES:
                raise ValueError(
                    f"line {line_number}: status must be one of {sorted(VALID_STATUSES)}"
                )
            start = finite_number(source.get("start_ms"), "start_ms", line_number)
            end = finite_number(source.get("end_ms"), "end_ms", line_number)
            if end < start:
                raise ValueError(f"line {line_number}: end_ms cannot precede start_ms")

            parent = source.get("parent_span_id")
            if parent is not None and (not isinstance(parent, str) or not parent.strip()):
                raise ValueError(f"line {line_number}: parent_span_id must be a non-empty string")
            tool = source.get("tool")
            if tool is not None and (not isinstance(tool, str) or not tool.strip()):
                raise ValueError(f"line {line_number}: tool must be a non-empty string")

            findings.extend(
                sensitive_findings(source, trace_id=trace_id, span_id=span_id)
            )
            spans.append(
                {
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "parent_span_id": parent.strip() if isinstance(parent, str) else None,
                    "name": name,
                    "status": status,
                    "start_ms": start,
                    "end_ms": end,
                    "duration_ms": end - start,
                    "tool": tool.strip() if isinstance(tool, str) else None,
                }
            )
    if not spans:
        raise ValueError("input contains no spans")
    unique_findings = [dict(items) for items in sorted({tuple(item.items()) for item in findings})]
    return spans, unique_findings


def connected_components(
    identifiers: set[str], parent_by_span: dict[str, str | None]
) -> list[list[str]]:
    neighbors: dict[str, set[str]] = {span_id: set() for span_id in identifiers}
    for span_id, parent_id in parent_by_span.items():
        if parent_id in identifiers:
            neighbors[span_id].add(parent_id)
            neighbors[parent_id].add(span_id)
    remaining = set(identifiers)
    components: list[list[str]] = []
    while remaining:
        start = min(remaining)
        queue = deque([start])
        remaining.remove(start)
        component: list[str] = []
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbor in sorted(neighbors[current]):
                if neighbor in remaining:
                    remaining.remove(neighbor)
                    queue.append(neighbor)
        components.append(sorted(component))
    return sorted(components, key=lambda item: item[0])


def cycle_span_ids(parent_by_span: dict[str, str | None]) -> list[str]:
    state: dict[str, int] = {}
    stack: list[str] = []
    position: dict[str, int] = {}
    in_cycles: set[str] = set()

    def visit(span_id: str) -> None:
        state[span_id] = 1
        position[span_id] = len(stack)
        stack.append(span_id)
        parent = parent_by_span[span_id]
        if parent in parent_by_span:
            parent_state = state.get(parent, 0)
            if parent_state == 0:
                visit(parent)
            elif parent_state == 1:
                in_cycles.update(stack[position[parent] :])
        stack.pop()
        position.pop(span_id, None)
        state[span_id] = 2

    for span_id in sorted(parent_by_span):
        if state.get(span_id, 0) == 0:
            visit(span_id)
    return sorted(in_cycles)


def analyze_structure(spans: list[dict[str, Any]]) -> dict[str, Any]:
    by_trace: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for span in spans:
        by_trace[span["trace_id"]].append(span)

    traces: dict[str, Any] = {}
    for trace_id, group in sorted(by_trace.items()):
        parent_by_span = {span["span_id"]: span["parent_span_id"] for span in group}
        identifiers = set(parent_by_span)
        roots = sorted(span_id for span_id, parent in parent_by_span.items() if parent is None)
        missing_edges = sorted(
            f"{span_id}->{parent}"
            for span_id, parent in parent_by_span.items()
            if parent is not None and parent not in identifiers
        )
        cycles = cycle_span_ids(parent_by_span)
        components = connected_components(identifiers, parent_by_span)

        reachable: set[str] = set()
        children: dict[str, list[str]] = defaultdict(list)
        for span_id, parent in parent_by_span.items():
            if parent in identifiers:
                children[parent].append(span_id)
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            queue.extend(children[current])
        unreachable = sorted(identifiers - reachable)

        issues: list[str] = []
        if len(roots) != 1:
            issues.append(f"expected exactly one root span, found {len(roots)}")
        if missing_edges:
            issues.append(f"found {len(missing_edges)} missing parent reference(s)")
        if cycles:
            issues.append(f"found a parent cycle involving {len(cycles)} span(s)")
        if len(components) != 1:
            issues.append(f"found {len(components)} disconnected graph components")
        if unreachable:
            issues.append(f"found {len(unreachable)} span(s) unreachable from any root")
        traces[trace_id] = {
            "structurally_valid": not issues,
            "root_count": len(roots),
            "root_span_ids": roots,
            "component_count": len(components),
            "components": components,
            "missing_parent_edges": missing_edges,
            "cycle_span_ids": cycles,
            "unreachable_from_roots": unreachable,
            "issues": issues,
        }

    invalid_trace_count = sum(not trace["structurally_valid"] for trace in traces.values())
    return {
        "structurally_valid": invalid_trace_count == 0,
        "trace_count": len(traces),
        "invalid_trace_count": invalid_trace_count,
        "traces": traces,
    }


def duration_summary(values: list[float]) -> dict[str, float]:
    return {
        "mean": fmean(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "max": max(values),
    }


def summarize(
    spans: list[dict[str, Any]], findings: list[dict[str, str]]
) -> dict[str, Any]:
    by_trace: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for span in spans:
        by_trace[span["trace_id"]].append(span)
    trace_envelopes = [
        max(span["end_ms"] for span in trace) - min(span["start_ms"] for span in trace)
        for trace in by_trace.values()
    ]
    errors = sum(span["status"] == "error" for span in spans)
    structure = analyze_structure(spans)
    result: dict[str, Any] = {
        "structure": structure,
        "scope": (
            "Structural and descriptive telemetry checks only. Observed envelopes are not "
            "causal end-to-end latency, and absence of a sensitive-field finding is not proof of redaction."
        ),
        "trace_count": len(by_trace),
        "span_count": len(spans),
        "error_span_count": errors,
        "error_span_rate": errors / len(spans),
        "trace_observed_envelope_ms": duration_summary(trace_envelopes),
        "span_duration_ms": duration_summary([span["duration_ms"] for span in spans]),
        "status_counts": dict(sorted(Counter(span["status"] for span in spans).items())),
        "sensitive_field_audit": {
            "finding_count": len(findings),
            "findings": findings,
            "note": "Only field paths and reason classes are emitted; suspected values are never copied.",
        },
    }

    names: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tools: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for span in spans:
        names[span["name"]].append(span)
        if span["tool"]:
            tools[span["tool"]].append(span)
    result["operations"] = {
        name: {
            "count": len(group),
            "error_count": sum(span["status"] == "error" for span in group),
            "duration_ms_p95": percentile([span["duration_ms"] for span in group], 0.95),
        }
        for name, group in sorted(names.items())
    }
    result["tools"] = {
        tool: {
            "count": len(group),
            "error_count": sum(span["status"] == "error" for span in group),
            "duration_ms_p95": percentile([span["duration_ms"] for span in group], 0.95),
        }
        for tool, group in sorted(tools.items())
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSONL file with one span per line")
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON path (written atomically; must not alias the input)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also fail when likely sensitive fields or secret-like values are detected",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        spans, findings = load_spans(args.input)
        result = summarize(spans, findings)
        payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            write_text_atomic(args.input, args.output, payload)
        else:
            sys.stdout.write(payload)
        if not result["structure"]["structurally_valid"]:
            return 1
        if args.strict and findings:
            return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
