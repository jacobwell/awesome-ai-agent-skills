#!/usr/bin/env python3
"""Validate and structurally summarize agent-evaluation JSON Lines results."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from statistics import fmean, median, pstdev, stdev
from typing import Any


Z_95 = 1.959963984540054


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


def optional_text(record: dict[str, Any], field: str, line_number: int) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"line {line_number}: {field} must be a non-empty string when provided")
    return value.strip()


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def load_records(
    path: Path,
    *,
    score_min: float,
    score_max: float,
    require_passed: bool,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_identities: dict[tuple[str, ...], int] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"line {line_number}: record must be an object")

            case_id = optional_text(record, "case_id", line_number)
            if case_id is None:
                raise ValueError(f"line {line_number}: case_id must be a non-empty string")
            run_id = optional_text(record, "run_id", line_number)
            record_id = optional_text(record, "record_id", line_number)
            variant = optional_text(record, "variant", line_number) or "default"

            # A supplied record_id is globally unique. Otherwise, case + variant +
            # run is the record identity. A missing run_id means one run only.
            identity = (
                ("record_id", record_id)
                if record_id is not None
                else ("case_run", case_id, variant, run_id or "single")
            )
            if identity in seen_identities:
                first_line = seen_identities[identity]
                raise ValueError(
                    f"line {line_number}: duplicate record identity also seen on line {first_line}: "
                    f"{identity[1:]!r}"
                )
            seen_identities[identity] = line_number

            score = finite_number(record.get("score"), "score", line_number)
            if not score_min <= score <= score_max:
                raise ValueError(
                    f"line {line_number}: score {score} is outside declared bounds "
                    f"[{score_min}, {score_max}]"
                )

            normalized = dict(record)
            normalized.update(
                {
                    "case_id": case_id,
                    "run_id": run_id,
                    "record_id": record_id,
                    "variant": variant,
                    "score": score,
                }
            )

            if "passed" in record and not isinstance(record["passed"], bool):
                raise ValueError(f"line {line_number}: passed must be a boolean")
            if require_passed and "passed" not in record:
                raise ValueError(f"line {line_number}: passed is required by --require-passed")
            for field in ("latency_ms", "cost_usd"):
                if field in record:
                    value = finite_number(record[field], field, line_number)
                    if value < 0:
                        raise ValueError(f"line {line_number}: {field} cannot be negative")
                    normalized[field] = value
            category = optional_text(record, "category", line_number) or "uncategorized"
            normalized["category"] = category
            records.append(normalized)
    if not records:
        raise ValueError("input contains no records")
    return records


def mean_ci95_normal(values: list[float]) -> list[float] | None:
    if len(values) < 2:
        return None
    margin = Z_95 * stdev(values) / math.sqrt(len(values))
    center = fmean(values)
    return [center - margin, center + margin]


def score_summary(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "mean": fmean(values),
        "mean_ci95_normal_approx": mean_ci95_normal(values),
        "median": median(values),
        "std_dev_population": pstdev(values),
        "min": min(values),
        "max": max(values),
    }


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + Z_95**2 / total
    center = (proportion + Z_95**2 / (2 * total)) / denominator
    margin = (
        Z_95
        * math.sqrt(proportion * (1 - proportion) / total + Z_95**2 / (4 * total**2))
        / denominator
    )
    return [max(0.0, center - margin), min(1.0, center + margin)]


def pass_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    observed = [record["passed"] for record in records if "passed" in record]
    passed_count = sum(observed)
    return {
        "value_observed_records": passed_count / len(observed) if observed else None,
        "passed_records": passed_count,
        "observed_records": len(observed),
        "missing_records": len(records) - len(observed),
        "total_records": len(records),
        "ci95_wilson_observed_records": wilson_interval(passed_count, len(observed)),
    }


def comparison_summary(
    records: list[dict[str, Any]], baseline: str, candidate: str
) -> dict[str, Any]:
    baseline_scores = [record["score"] for record in records if record["variant"] == baseline]
    candidate_scores = [record["score"] for record in records if record["variant"] == candidate]
    if not baseline_scores:
        raise ValueError(f"no records found for baseline variant {baseline!r}")
    if not candidate_scores:
        raise ValueError(f"no records found for candidate variant {candidate!r}")

    delta = fmean(candidate_scores) - fmean(baseline_scores)
    delta_interval: list[float] | None = None
    if len(baseline_scores) >= 2 and len(candidate_scores) >= 2:
        standard_error = math.sqrt(
            stdev(baseline_scores) ** 2 / len(baseline_scores)
            + stdev(candidate_scores) ** 2 / len(candidate_scores)
        )
        delta_interval = [delta - Z_95 * standard_error, delta + Z_95 * standard_error]

    return {
        "baseline_variant": baseline,
        "candidate_variant": candidate,
        "baseline": score_summary(baseline_scores),
        "candidate": score_summary(candidate_scores),
        "candidate_minus_baseline_mean": delta,
        "candidate_minus_baseline_ci95_normal_approx_independent": delta_interval,
        "uncertainty_note": (
            "Intervals are descriptive normal approximations, not proof of significance; "
            "account for pairing, clustering, repeated runs, and the sampling design separately."
        ),
    }


def summarize(
    records: list[dict[str, Any]],
    *,
    score_min: float,
    score_max: float,
    baseline: str | None,
    candidate: str | None,
) -> dict[str, Any]:
    scores = [record["score"] for record in records]
    summary: dict[str, Any] = {
        "structurally_valid": True,
        "scope": (
            "Descriptive aggregation only. This output does not certify release readiness, "
            "safety, statistical significance, or dataset representativeness."
        ),
        "count": len(records),
        "unique_cases": len({record["case_id"] for record in records}),
        "score_bounds": {"minimum": score_min, "maximum": score_max, "inclusive": True},
        "score": score_summary(scores),
        "pass_rate": pass_summary(records),
    }

    latencies = [record["latency_ms"] for record in records if "latency_ms" in record]
    if latencies:
        summary["latency_ms"] = {
            "observed_records": len(latencies),
            "missing_records": len(records) - len(latencies),
            "total_records": len(records),
            "mean": fmean(latencies),
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "max": max(latencies),
        }

    costs = [record["cost_usd"] for record in records if "cost_usd" in record]
    if costs:
        summary["cost_usd"] = {
            "observed_records": len(costs),
            "missing_records": len(records) - len(costs),
            "total_records": len(records),
            "sum_observed_records": sum(costs),
            "mean_observed_records": fmean(costs),
        }

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[record["category"]].append(record)
    summary["categories"] = {
        category: {
            "count": len(group),
            "score": score_summary([record["score"] for record in group]),
            "pass_rate": pass_summary(group),
        }
        for category, group in sorted(groups.items())
    }

    if baseline is not None and candidate is not None:
        summary["baseline_comparison"] = comparison_summary(records, baseline, candidate)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSONL file with one evaluation result per line")
    parser.add_argument(
        "--score-min", type=float, default=0.0, help="Inclusive score minimum (default: 0)"
    )
    parser.add_argument(
        "--score-max", type=float, default=1.0, help="Inclusive score maximum (default: 1)"
    )
    parser.add_argument(
        "--require-passed",
        action="store_true",
        help="Reject records that omit the passed boolean",
    )
    parser.add_argument("--baseline", help="Variant label to treat as the baseline")
    parser.add_argument("--candidate", help="Variant label to compare with --baseline")
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON path (written atomically; must not alias the input)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        score_min = finite_number(args.score_min, "--score-min", 0)
        score_max = finite_number(args.score_max, "--score-max", 0)
        if score_min >= score_max:
            raise ValueError("--score-min must be less than --score-max")
        if (args.baseline is None) != (args.candidate is None):
            raise ValueError("--baseline and --candidate must be provided together")
        if args.baseline is not None and args.baseline == args.candidate:
            raise ValueError("--baseline and --candidate must be different labels")

        records = load_records(
            args.input,
            score_min=score_min,
            score_max=score_max,
            require_passed=args.require_passed,
        )
        payload = json.dumps(
            summarize(
                records,
                score_min=score_min,
                score_max=score_max,
                baseline=args.baseline,
                candidate=args.candidate,
            ),
            indent=2,
            sort_keys=True,
        ) + "\n"
        if args.output:
            write_text_atomic(args.input, args.output, payload)
        else:
            sys.stdout.write(payload)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
