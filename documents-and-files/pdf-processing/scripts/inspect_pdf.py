#!/usr/bin/env python3
"""Inspect PDF structure without modifying or activating document content.

The default mode uses byte-level heuristics only. --deep may invoke an installed
PDF parser or pdfinfo. Untrusted inputs require a separately verified sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable


ACTIVE_MARKERS = {
    "javascript": rb"/JavaScript\b|/JS\b",
    "open_action": rb"/OpenAction\b",
    "additional_actions": rb"/AA\b",
    "launch_action": rb"/Launch\b",
    "embedded_files": rb"/EmbeddedFiles\b|/Filespec\b",
    "rich_media": rb"/RichMedia\b|/Movie\b|/Sound\b",
    "acroform": rb"/AcroForm\b",
    "xfa": rb"/XFA\b",
}
TOOL_NAMES = ("pdfinfo", "pdftotext", "pdftoppm", "qpdf", "mutool", "gs", "ocrmypdf", "tesseract", "verapdf")
MODULE_NAMES = ("pypdf", "PyPDF2", "fitz", "pdfplumber")
MAX_RAW_SCAN_BYTES = 100_000_000


class OutputPathError(Exception):
    """Raised when a report destination could overwrite the inspected input."""


def lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.path.normpath(os.fspath(path))))


def resolved_path(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise OutputPathError(f"cannot resolve path safely: {path}: {exc}") from exc


def validate_output_path(output: Path, inputs: Iterable[Path]) -> Path:
    output_lexical = lexical_path(output)
    output_resolved = resolved_path(output)
    try:
        output_stat = output.lstat()
    except FileNotFoundError:
        output_exists = False
    except OSError as exc:
        raise OutputPathError(f"cannot inspect output path: {output}: {exc}") from exc
    else:
        output_exists = True
        if not stat.S_ISREG(output_stat.st_mode):
            raise OutputPathError(f"output exists and is not a regular file: {output}")

    for source in inputs:
        if output_lexical == lexical_path(source) or output_resolved == resolved_path(source):
            raise OutputPathError(f"output aliases an input path: {output}")
        if output_exists and source.exists():
            try:
                if os.path.samefile(output, source):
                    raise OutputPathError(f"output aliases an input inode: {output}")
            except OutputPathError:
                raise
            except OSError as exc:
                raise OutputPathError(
                    f"cannot safely compare output and input paths: {output}: {exc}"
                ) from exc

    parent = output_lexical.parent
    if not parent.exists():
        raise OutputPathError(f"output directory does not exist: {parent}")
    if not parent.is_dir():
        raise OutputPathError(f"output parent is not a directory: {parent}")
    return output_resolved


def atomic_write_text(output: Path, payload: str, inputs: Iterable[Path]) -> None:
    input_paths = tuple(inputs)
    destination = validate_output_path(output, input_paths)
    parent = destination.parent
    temp_path: Path | None = None
    try:
        file_descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=parent
        )
        temp_path = Path(temp_name)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        destination = validate_output_path(output, input_paths)
        if destination.parent != parent:
            raise OutputPathError(f"output directory changed during write: {output.parent}")
        os.replace(temp_path, destination)
        temp_path = None
    except OutputPathError:
        raise
    except OSError as exc:
        raise OutputPathError(f"unable to write output atomically: {output}: {exc}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_inspection(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        data = handle.read(MAX_RAW_SCAN_BYTES)
        if size > 4096:
            handle.seek(-4096, 2)
        else:
            handle.seek(0)
        tail = handle.read()
    scan_complete = len(data) == size
    header_match = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    page_objects = len(re.findall(rb"/Type\s*/Page(?!s)\b", data))
    pages_nodes = len(re.findall(rb"/Type\s*/Pages\b", data))
    eof_near_end = b"%%EOF" in tail
    startxref_near_end = b"startxref" in tail
    incremental_updates = max(0, len(re.findall(rb"%%EOF", data)) - 1)
    markers = {
        name: len(re.findall(pattern, data))
        for name, pattern in ACTIVE_MARKERS.items()
    }
    warnings: list[str] = []
    if not header_match:
        warnings.append("No PDF header was found in the first 1024 bytes.")
    if not eof_near_end:
        warnings.append("No %%EOF marker was found in the final 4096 bytes.")
    if not startxref_near_end:
        warnings.append("No startxref marker was found in the final 4096 bytes.")
    if not scan_complete:
        warnings.append(
            f"Feature and page-object scanning was limited to the first {MAX_RAW_SCAN_BYTES} bytes; later objects were not inspected."
        )
    if incremental_updates:
        warnings.append("Multiple EOF markers suggest incremental revisions; old content may remain in the file.")
    if any(markers[name] for name in ("javascript", "open_action", "additional_actions", "launch_action", "embedded_files", "rich_media")):
        warnings.append("Potential active or embedded content markers are present; do not activate them during review.")
    if b"/Encrypt" in data:
        warnings.append("An encryption dictionary marker is present; content and permissions may require a password.")
    return {
        "header_version": header_match.group(1).decode("ascii") if header_match else None,
        "eof_near_end": eof_near_end,
        "startxref_near_end": startxref_near_end,
        "page_count": page_objects if page_objects else None,
        "page_count_method": "raw /Type /Page object count (heuristic)",
        "bytes_scanned_for_objects": len(data),
        "object_scan_complete": scan_complete,
        "pages_tree_nodes": pages_nodes,
        "encrypted_marker": b"/Encrypt" in data,
        "linearized_marker": b"/Linearized" in data[:4096],
        "incremental_update_markers": incremental_updates,
        "feature_markers": markers,
        "warnings": warnings,
    }


def parser_inventory() -> dict[str, Any]:
    return {
        "commands": {name: shutil.which(name) for name in TOOL_NAMES},
        "python_modules": {name: importlib.util.find_spec(name) is not None for name in MODULE_NAMES},
    }


def deep_with_pypdf(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    reader_class = None
    parser_name = None
    try:
        from pypdf import PdfReader  # type: ignore
        reader_class = PdfReader
        parser_name = "pypdf"
    except ImportError:
        try:
            from PyPDF2 import PdfReader  # type: ignore
            reader_class = PdfReader
            parser_name = "PyPDF2"
        except ImportError:
            return None, "Neither pypdf nor PyPDF2 is installed."
    try:
        reader = reader_class(str(path), strict=False)
        encrypted = bool(reader.is_encrypted)
        result: dict[str, Any] = {
            "method": parser_name,
            "encrypted": encrypted,
            "page_count": None,
            "metadata_keys": [],
        }
        if not encrypted:
            result["page_count"] = len(reader.pages)
            metadata = reader.metadata or {}
            result["metadata_keys"] = sorted(str(key) for key in metadata.keys())
        return result, None
    except Exception as exc:  # Parser errors must be reported, not hidden.
        return None, f"{parser_name} could not parse the file: {type(exc).__name__}: {exc}"


def deep_with_pdfinfo(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    executable = shutil.which("pdfinfo")
    if not executable:
        return None, "pdfinfo is not installed."
    try:
        completed = subprocess.run(
            [executable, str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"pdfinfo failed: {type(exc).__name__}: {exc}"
    fields: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip().lower().replace(" ", "_")] = value.strip()
    result = {
        "method": "pdfinfo",
        "exit_code": completed.returncode,
        "fields": fields,
    }
    error = completed.stderr.strip() or None
    return result, error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pdf", type=Path, help="PDF file to inspect read-only")
    parser.add_argument("--deep", action="store_true", help="Also invoke an installed parser/pdfinfo")
    parser.add_argument(
        "--trust-level", choices=("untrusted", "trusted"), default="untrusted",
        help="Input trust decision; defaults to untrusted",
    )
    parser.add_argument(
        "--sandbox-profile-confirmed", action="store_true",
        help="Confirm the documented no-network/no-active-content sandbox profile before deep parsing untrusted input",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Atomically write JSON to a regular file; input aliases are refused",
    )
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.pdf.is_file():
        print(f"error: file does not exist: {args.pdf}", file=sys.stderr)
        return 2
    if args.output:
        try:
            validate_output_path(args.output, [args.pdf])
        except OutputPathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.deep and args.trust_level == "untrusted" and not args.sandbox_profile_confirmed:
        print(
            "error: deep parsing of an untrusted PDF requires --sandbox-profile-confirmed; "
            "otherwise run the default raw-byte inspection only",
            file=sys.stderr,
        )
        return 2
    try:
        raw = raw_inspection(args.pdf)
    except OSError as exc:
        print(f"error: unable to read {args.pdf}: {exc}", file=sys.stderr)
        return 2
    report: dict[str, Any] = {
        "path": str(args.pdf.resolve()),
        "bytes": args.pdf.stat().st_size,
        "sha256": sha256(args.pdf),
        "modified": False,
        "trust_level": args.trust_level,
        "sandbox_profile_confirmed": args.sandbox_profile_confirmed,
        "inspection_mode": "deep" if args.deep else "raw-byte heuristic",
        "raw": raw,
        "available_capabilities": parser_inventory(),
        "limitations": [
            "Raw feature markers and page-object counts can be false positives or incomplete.",
            "The inspector does not render pages, extract text, validate signatures, or prove redaction.",
            "Active content is reported but never activated.",
            "Sandbox confirmation is an operator assertion; this script cannot verify host isolation or parser configuration.",
        ],
    }
    if args.deep:
        parser_result, parser_error = deep_with_pypdf(args.pdf)
        pdfinfo_result, pdfinfo_error = deep_with_pdfinfo(args.pdf)
        report["deep"] = {
            "python_parser": parser_result,
            "python_parser_error": parser_error,
            "pdfinfo": pdfinfo_result,
            "pdfinfo_error": pdfinfo_error,
        }
    payload = json.dumps(report, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        try:
            validate_output_path(args.output, [args.pdf])
            atomic_write_text(args.output, payload, [args.pdf])
        except OutputPathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
