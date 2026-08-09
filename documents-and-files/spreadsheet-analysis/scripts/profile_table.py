#!/usr/bin/env python3
"""Create a bounded, read-only profile of CSV/TSV/XLSX/XLSM files.

The profiler uses only the Python standard library. It streams delimited records,
never calculates formulas, refreshes links, executes macros, or modifies input.
"""

from __future__ import annotations

import argparse
import codecs
import csv
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any, Iterable
import xml.etree.ElementTree as ET
import zipfile


FORMULA_RISK_PATTERNS = {
    "external_workbook_reference": re.compile(r"\[[^\]]+\]"),
    "webservice": re.compile(r"\bWEBSERVICE\s*\(", re.I),
    "hyperlink": re.compile(r"\bHYPERLINK\s*\(", re.I),
    "realtime_or_external_data": re.compile(r"\b(?:RTD|FILTERXML|STOCKHISTORY)\s*\(", re.I),
    "legacy_command_or_dde": re.compile(r"(?:\|\s*['\"]?[^!]+!|\b(?:CALL|EXEC|REGISTER)\s*\()", re.I),
}
DEFAULT_MAX_INPUT_BYTES = 1_000_000_000
DEFAULT_MAX_ROWS = 100_000
DEFAULT_MAX_XLSX_ROWS_PER_SHEET = 1_000_000
SNIFF_BYTES = 65_536
MAX_CSV_FIELD_CHARS = 1_000_000
MAX_CSV_RECORD_CHARS = 8_000_000
MAX_CSV_COLUMNS = 4_096
MAX_UNIQUE_PER_COLUMN = 1_000
MAX_UNIQUE_TOTAL = 100_000
MAX_XML_PART_BYTES = 50_000_000
MAX_PACKAGE_UNCOMPRESSED_BYTES = 1_000_000_000
MAX_ZIP_MEMBERS = 100_000
MAX_SHEETS = 1_000


class OutputPathError(Exception):
    """Raised when a report destination could overwrite the profiled input."""


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


class RecordResourceLimitError(Exception):
    """Raised before csv.reader can accumulate an oversized logical record."""


class BoundedPhysicalLineIterator:
    """Feed csv.reader complete physical lines within a per-record budget."""

    def __init__(self, handle: Any, max_record_chars: int) -> None:
        self.handle = handle
        self.max_record_chars = max_record_chars
        self.record_chars = 0

    def __iter__(self) -> "BoundedPhysicalLineIterator":
        return self

    def __next__(self) -> str:
        line = self.handle.readline(self.max_record_chars + 1)
        if line == "":
            raise StopIteration
        if len(line) > self.max_record_chars:
            raise RecordResourceLimitError(
                f"physical line exceeds {self.max_record_chars} characters"
            )
        self.record_chars += len(line)
        if self.record_chars > self.max_record_chars:
            raise RecordResourceLimitError(
                f"quoted logical record exceeds {self.max_record_chars} characters"
            )
        return line

    def reset_record(self) -> None:
        self.record_chars = 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def safe_xml_info(archive: zipfile.ZipFile, name: str) -> zipfile.ZipInfo:
    info = archive.getinfo(name)
    if info.file_size > MAX_XML_PART_BYTES:
        raise ValueError(f"XML part exceeds {MAX_XML_PART_BYTES} bytes: {name}")
    ratio = info.file_size / max(info.compress_size, 1)
    if info.file_size > 10_000_000 and ratio > 100:
        raise ValueError(f"XML part has a suspicious compression ratio: {name}")
    return info


def safe_read_xml(archive: zipfile.ZipFile, name: str) -> bytes:
    safe_xml_info(archive, name)
    return archive.read(name)


def detect_delimited_encoding(path: Path) -> tuple[str, str, list[str]]:
    """Inspect a bounded prefix; do not read or decode the whole input."""
    warnings: list[str] = []
    with path.open("rb") as handle:
        raw = handle.read(SNIFF_BYTES)
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding, label = "utf-32", "utf-32 (BOM)"
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding, label = "utf-16", "utf-16 (BOM)"
    elif raw.startswith(codecs.BOM_UTF8):
        encoding, label = "utf-8-sig", "utf-8 (BOM)"
    else:
        try:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
            decoder.decode(raw, final=False)
            encoding, label = "utf-8", "utf-8 (prefix check)"
        except UnicodeDecodeError:
            encoding, label = "cp1252", "cp1252 fallback"
            warnings.append(
                "The bounded prefix was not valid UTF-8; Windows-1252 was selected. Confirm the source encoding."
            )
    sample = raw.decode(encoding, errors="replace")
    return encoding, label, warnings + ([
        "Encoding and delimiter detection use a bounded prefix; later malformed bytes are reported if encountered."
    ] if len(raw) == SNIFF_BYTES else [])


def value_type(value: str) -> tuple[str, Decimal | None]:
    stripped = value.strip()
    if not stripped:
        return "blank", None
    if stripped.lower() in {"true", "false", "yes", "no"}:
        return "boolean-like", None
    if len(stripped) > 1 and stripped[0] == "0" and stripped.isdigit():
        return "text", None
    try:
        number = Decimal(stripped.replace(",", ""))
        return "integer-like" if number == number.to_integral_value() else "decimal-like", number
    except InvalidOperation:
        pass
    for date_format in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            datetime.strptime(stripped, date_format)
            return "date-like", None
        except ValueError:
            continue
    return "text", None


def serialize_columns(columns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for source in columns:
        column = dict(source)
        unique_values = column.pop("unique_values")
        column["unique_count_lower_bound"] = len(unique_values)
        for key in ("numeric_min", "numeric_max"):
            if column[key] is not None:
                column[key] = str(column[key])
        result.append(column)
    return result


def profile_delimited(path: Path, max_rows: int) -> dict[str, Any]:
    encoding, encoding_label, warnings = detect_delimited_encoding(path)
    with path.open("rb") as sample_handle:
        sample_raw = sample_handle.read(SNIFF_BYTES)
    sample = sample_raw.decode(encoding, errors="replace")
    if path.suffix.lower() == ".tsv":
        dialect: Any = csv.excel_tab
        delimiter_source = "file extension"
    else:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
            delimiter_source = "csv.Sniffer bounded-prefix heuristic"
        except csv.Error:
            dialect = csv.excel
            delimiter_source = "fallback comma"
            warnings.append("Delimiter detection failed; comma was used as a fallback.")

    old_field_limit = csv.field_size_limit()
    csv.field_size_limit(MAX_CSV_FIELD_CHARS)
    try:
        with path.open("r", encoding=encoding, errors="replace", newline="") as handle:
            bounded_lines = BoundedPhysicalLineIterator(handle, MAX_CSV_RECORD_CHARS)
            reader = csv.reader(bounded_lines, dialect, strict=True)
            try:
                headers = next(reader)
                bounded_lines.reset_record()
            except StopIteration:
                return {
                    "kind": "delimited",
                    "status": "complete",
                    "profile_complete": True,
                    "encoding": encoding_label,
                    "delimiter": getattr(dialect, "delimiter", ","),
                    "header_columns": 0,
                    "data_rows_profiled": 0,
                    "physical_lines_consumed": reader.line_num,
                    "columns": [],
                    "limits": delimited_limits(max_rows),
                    "warnings": warnings + ["File is empty."],
                }
            except (csv.Error, RecordResourceLimitError) as exc:
                return delimited_parse_failure(encoding_label, dialect, max_rows, reader.line_num, warnings, exc)

            if len(headers) > MAX_CSV_COLUMNS:
                return {
                    "kind": "delimited",
                    "status": "stopped_resource_limit",
                    "profile_complete": False,
                    "encoding": encoding_label,
                    "delimiter": getattr(dialect, "delimiter", ","),
                    "header_columns": len(headers),
                    "data_rows_profiled": 0,
                    "physical_lines_consumed": reader.line_num,
                    "columns": [],
                    "limits": delimited_limits(max_rows),
                    "warnings": warnings + [
                        f"Header has {len(headers)} columns; profiling stopped at the {MAX_CSV_COLUMNS}-column safety limit."
                    ],
                }

            seen_headers: dict[str, int] = {}
            duplicate_headers: list[str] = []
            for header in headers:
                key = header.strip()
                seen_headers[key] = seen_headers.get(key, 0) + 1
                if seen_headers[key] == 2:
                    duplicate_headers.append(key)
            width = len(headers)
            columns: list[dict[str, Any]] = [
                {
                    "index": index + 1,
                    "header": header,
                    "nonblank": 0,
                    "blank": 0,
                    "formula_like": 0,
                    "types": {},
                    "numeric_min": None,
                    "numeric_max": None,
                    "unique_values": set(),
                    "unique_tracking_truncated": False,
                }
                for index, header in enumerate(headers)
            ]
            ragged_rows = 0
            data_rows = 0
            total_unique = 0
            replacement_char_seen = False
            status = "complete"
            profile_complete = True
            parse_error: str | None = None
            resource_limit_error: str | None = None
            while data_rows < max_rows:
                try:
                    row = next(reader)
                    bounded_lines.reset_record()
                except StopIteration:
                    break
                except (csv.Error, RecordResourceLimitError) as exc:
                    status = (
                        "stopped_resource_limit"
                        if isinstance(exc, RecordResourceLimitError)
                        else "stopped_parse_error"
                    )
                    profile_complete = False
                    message = f"{type(exc).__name__}: {exc} (near physical line {reader.line_num})"
                    if isinstance(exc, RecordResourceLimitError):
                        resource_limit_error = message
                    else:
                        parse_error = message
                    break
                record_chars = sum(len(value) for value in row)
                if record_chars > MAX_CSV_RECORD_CHARS:
                    status = "stopped_resource_limit"
                    profile_complete = False
                    warnings.append(
                        f"A logical record exceeded {MAX_CSV_RECORD_CHARS} characters; it was not profiled."
                    )
                    break
                data_rows += 1
                if len(row) != width:
                    ragged_rows += 1
                for index in range(width):
                    value = row[index] if index < len(row) else ""
                    replacement_char_seen = replacement_char_seen or "\ufffd" in value
                    column = columns[index]
                    stripped = value.strip()
                    kind, number = value_type(value)
                    column["types"][kind] = column["types"].get(kind, 0) + 1
                    if kind == "blank":
                        column["blank"] += 1
                    else:
                        column["nonblank"] += 1
                        if stripped.startswith(("=", "@")) or (
                            stripped.startswith(("+", "-")) and number is None
                        ):
                            column["formula_like"] += 1
                        unique_values = column["unique_values"]
                        if len(unique_values) < MAX_UNIQUE_PER_COLUMN and total_unique < MAX_UNIQUE_TOTAL:
                            before = len(unique_values)
                            unique_values.add(value)
                            total_unique += len(unique_values) - before
                        else:
                            column["unique_tracking_truncated"] = True
                    if number is not None:
                        current_min = column["numeric_min"]
                        current_max = column["numeric_max"]
                        column["numeric_min"] = number if current_min is None or number < current_min else current_min
                        column["numeric_max"] = number if current_max is None or number > current_max else current_max
            else:
                # Do not request one more logical record merely to distinguish exact EOF
                # from truncation: that record may itself be adversarially large.
                status = "row_limit_reached"
                profile_complete = False
                warnings.append(
                    f"Profiling stopped at {max_rows} logical data rows without reading another record; additional rows may exist."
                )

            serializable_columns = serialize_columns(columns)
            if duplicate_headers:
                warnings.append("Duplicate header labels are present.")
            if ragged_rows:
                warnings.append("Rows with a different field count than the header are present.")
            if any(column["formula_like"] for column in serializable_columns):
                warnings.append("Formula-like text is present; sanitize untrusted exports before spreadsheet use.")
            if any(column["unique_tracking_truncated"] for column in serializable_columns):
                warnings.append("Unique-value tracking reached its bounded memory budget; counts are lower bounds.")
            if replacement_char_seen:
                warnings.append("Unicode replacement characters were observed; confirm encoding and source integrity.")
            if parse_error:
                warnings.append("CSV parsing stopped safely; results cover only the preceding complete logical records.")
            if resource_limit_error:
                warnings.append("CSV profiling stopped at a record resource limit; preceding summaries remain partial.")
            return {
                "kind": "delimited",
                "status": status,
                "profile_complete": profile_complete,
                "encoding": encoding_label,
                "delimiter": getattr(dialect, "delimiter", ","),
                "delimiter_source": delimiter_source,
                "header_columns": width,
                "data_rows_profiled": data_rows,
                "physical_lines_consumed": reader.line_num,
                "ragged_rows": ragged_rows,
                "duplicate_headers": duplicate_headers,
                "parse_error": parse_error,
                "resource_limit_error": resource_limit_error,
                "columns": serializable_columns,
                "limits": delimited_limits(max_rows),
                "warnings": warnings,
            }
    finally:
        csv.field_size_limit(old_field_limit)


def delimited_limits(max_rows: int) -> dict[str, int]:
    return {
        "max_logical_data_rows": max_rows,
        "max_columns": MAX_CSV_COLUMNS,
        "max_field_characters": MAX_CSV_FIELD_CHARS,
        "max_record_characters": MAX_CSV_RECORD_CHARS,
        "max_unique_values_per_column": MAX_UNIQUE_PER_COLUMN,
        "max_unique_values_total": MAX_UNIQUE_TOTAL,
        "sniff_bytes": SNIFF_BYTES,
    }


def delimited_parse_failure(
    encoding: str, dialect: Any, max_rows: int, line_num: int, warnings: list[str], exc: Exception
) -> dict[str, Any]:
    resource_limited = isinstance(exc, RecordResourceLimitError)
    return {
        "kind": "delimited",
        "status": "stopped_resource_limit" if resource_limited else "stopped_parse_error",
        "profile_complete": False,
        "encoding": encoding,
        "delimiter": getattr(dialect, "delimiter", ","),
        "header_columns": None,
        "data_rows_profiled": 0,
        "physical_lines_consumed": line_num,
        "parse_error": None if resource_limited else f"{type(exc).__name__}: {exc}",
        "resource_limit_error": f"{type(exc).__name__}: {exc}" if resource_limited else None,
        "columns": [],
        "limits": delimited_limits(max_rows),
        "warnings": warnings + ["CSV parsing stopped safely before a complete header was available."],
    }


def workbook_relationships(archive: zipfile.ZipFile) -> dict[str, str]:
    try:
        root = ET.fromstring(safe_read_xml(archive, "xl/_rels/workbook.xml.rels"))
    except (KeyError, ET.ParseError, ValueError):
        return {}
    relationships: dict[str, str] = {}
    for rel in root:
        rel_id = rel.attrib.get("Id")
        target = rel.attrib.get("Target")
        if rel_id and target:
            relationships[rel_id] = target.lstrip("/")
    return relationships


def normalized_sheet_target(target: str) -> str:
    path = PurePosixPath(target)
    if str(path).startswith("xl/"):
        return str(path)
    return str(PurePosixPath("xl") / path)


def dimension_max_row(reference: str | None) -> int | None:
    if not reference:
        return None
    matches = re.findall(r"\$?[A-Z]+\$?(\d+)", reference.upper())
    return max((int(value) for value in matches), default=None)


def profile_sheet(archive: zipfile.ZipFile, target: str, max_rows: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target": target,
        "status": "complete",
        "profile_complete": True,
        "dimension": None,
        "dimension_declared_max_row": None,
        "rows_profiled": 0,
        "row_limit": max_rows,
        "row_limit_reached": False,
        "cells_profiled": 0,
        "formulas_profiled": 0,
        "error_cells_profiled": 0,
        "formula_risk_counts": {key: 0 for key in FORMULA_RISK_PATTERNS},
    }
    try:
        safe_xml_info(archive, target)
        with archive.open(target) as handle:
            for event, elem in ET.iterparse(handle, events=("start", "end")):
                name = local_name(elem.tag)
                if event == "start" and name == "dimension":
                    result["dimension"] = elem.attrib.get("ref")
                    result["dimension_declared_max_row"] = dimension_max_row(result["dimension"])
                elif event == "start" and name == "row":
                    if result["rows_profiled"] >= max_rows:
                        result["status"] = "row_limit_reached"
                        result["profile_complete"] = False
                        result["row_limit_reached"] = True
                        break
                    result["rows_profiled"] += 1
                elif event == "start" and name == "c":
                    result["cells_profiled"] += 1
                    if elem.attrib.get("t") == "e":
                        result["error_cells_profiled"] += 1
                elif event == "end" and name == "f":
                    result["formulas_profiled"] += 1
                    formula = elem.text or ""
                    for risk, pattern in FORMULA_RISK_PATTERNS.items():
                        if pattern.search(formula):
                            result["formula_risk_counts"][risk] += 1
                    elem.clear()
                elif event == "end":
                    elem.clear()
    except (KeyError, ET.ParseError, OSError, ValueError) as exc:
        result["status"] = "stopped_parse_or_resource_error"
        result["profile_complete"] = False
        result["parse_error"] = f"{type(exc).__name__}: {exc}"
    result["formula_risk_counts"] = {
        key: value for key, value in result["formula_risk_counts"].items() if value
    }
    if result["dimension_declared_max_row"] and result["dimension_declared_max_row"] > max_rows:
        result["dimension_exceeds_row_limit"] = True
    else:
        result["dimension_exceeds_row_limit"] = False
    return result


def profile_xlsx(path: Path, max_rows_per_sheet: int) -> dict[str, Any]:
    warnings: list[str] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        member_names = {info.filename for info in infos}
        unsafe_members = sorted(
            info.filename for info in infos
            if PurePosixPath(info.filename.replace("\\", "/")).is_absolute()
            or ".." in PurePosixPath(info.filename.replace("\\", "/")).parts
        )
        uncompressed_bytes = sum(info.file_size for info in infos)
        compressed_bytes = sum(info.compress_size for info in infos)
        high_ratio_members = sorted(
            info.filename for info in infos
            if info.file_size > 10_000_000 and info.file_size / max(info.compress_size, 1) > 100
        )
        has_macros = "xl/vbaProject.bin" in member_names or path.suffix.lower() == ".xlsm"
        external_links = sorted(name for name in member_names if name.startswith("xl/externalLinks/"))
        connections = "xl/connections.xml" in member_names
        base: dict[str, Any] = {
            "kind": "xlsx-package",
            "status": "complete",
            "profile_complete": True,
            "zip_members": len(infos),
            "compressed_bytes": compressed_bytes,
            "uncompressed_bytes": uncompressed_bytes,
            "unsafe_member_paths": unsafe_members,
            "high_compression_members": high_ratio_members,
            "has_macros": has_macros,
            "external_link_parts": external_links,
            "has_connections": connections,
            "has_pivot_cache": any(name.startswith("xl/pivotCache/") for name in member_names),
            "has_charts": any(name.startswith("xl/charts/") for name in member_names),
            "has_comments": any("comments" in name.lower() for name in member_names),
            "max_rows_profiled_per_sheet": max_rows_per_sheet,
            "sheets": [],
            "warnings": warnings,
        }
        if len(infos) > MAX_ZIP_MEMBERS or uncompressed_bytes > MAX_PACKAGE_UNCOMPRESSED_BYTES:
            base["status"] = "stopped_resource_limit"
            base["profile_complete"] = False
            if len(infos) > MAX_ZIP_MEMBERS:
                warnings.append(f"Package exceeds the {MAX_ZIP_MEMBERS}-member safety limit; XML was not parsed.")
            if uncompressed_bytes > MAX_PACKAGE_UNCOMPRESSED_BYTES:
                warnings.append(
                    f"Declared uncompressed size exceeds {MAX_PACKAGE_UNCOMPRESSED_BYTES} bytes; XML was not parsed."
                )
            return base

        relationships = workbook_relationships(archive)
        sheets: list[dict[str, Any]] = []
        calc_properties: dict[str, str] = {}
        defined_names = 0
        try:
            workbook_root = ET.fromstring(safe_read_xml(archive, "xl/workbook.xml"))
            for elem in workbook_root.iter():
                name = local_name(elem.tag)
                if name == "sheet":
                    if len(sheets) >= MAX_SHEETS:
                        warnings.append(f"Workbook exceeds the {MAX_SHEETS}-sheet profile limit.")
                        base["status"] = "stopped_resource_limit"
                        base["profile_complete"] = False
                        break
                    rel_id = next((value for key, value in elem.attrib.items() if local_name(key) == "id"), None)
                    target = normalized_sheet_target(relationships.get(rel_id or "", "")) if rel_id else ""
                    sheet = {
                        "name": elem.attrib.get("name"),
                        "state": elem.attrib.get("state", "visible"),
                        "relationship_id": rel_id,
                    }
                    if target:
                        sheet.update(profile_sheet(archive, target, max_rows_per_sheet))
                    else:
                        sheet.update({
                            "status": "unresolved_relationship",
                            "profile_complete": False,
                            "parse_error": "Worksheet relationship target was not resolved.",
                        })
                    sheets.append(sheet)
                elif name == "definedName":
                    defined_names += 1
                elif name == "calcPr":
                    calc_properties = dict(elem.attrib)
        except (KeyError, ET.ParseError, ValueError) as exc:
            base["status"] = "stopped_parse_or_resource_error"
            base["profile_complete"] = False
            warnings.append(f"Workbook XML could not be parsed: {type(exc).__name__}: {exc}")

        if unsafe_members:
            warnings.append("Archive contains unsafe absolute or parent-traversal member paths.")
        if high_ratio_members:
            warnings.append("Archive contains highly compressed large members; affected XML parts are not read.")
        if has_macros:
            warnings.append("Workbook contains or claims macro content; do not enable or execute it during inspection.")
        if external_links or connections:
            warnings.append("Workbook declares external links or connections; do not refresh them without authorization.")
        if any(sheet.get("state") != "visible" for sheet in sheets):
            warnings.append("Hidden or very-hidden sheets are present.")
        if any(sheet.get("formula_risk_counts") for sheet in sheets):
            warnings.append("Potential external, web, real-time, or legacy command formulas require manual review.")
        if any(not sheet.get("profile_complete", False) for sheet in sheets):
            base["profile_complete"] = False
            if base["status"] == "complete":
                base["status"] = "partial"
            warnings.append("One or more sheets were only partially inventoried; inspect their status and row-limit fields.")
        if any(sheet.get("dimension_exceeds_row_limit") for sheet in sheets):
            warnings.append("A declared worksheet dimension exceeds the configured row limit; full coverage is not claimed.")

        shared_strings = None
        if "xl/sharedStrings.xml" in member_names:
            try:
                safe_xml_info(archive, "xl/sharedStrings.xml")
                with archive.open("xl/sharedStrings.xml") as handle:
                    for _event, elem in ET.iterparse(handle, events=("start",)):
                        shared_strings = int(elem.attrib.get("uniqueCount", elem.attrib.get("count", "0")))
                        break
            except (ET.ParseError, ValueError):
                warnings.append("Shared string metadata could not be parsed safely.")
        base.update({
            "defined_names": defined_names,
            "shared_strings_declared": shared_strings,
            "calculation_properties": calc_properties,
            "sheets": sheets,
        })
        return base


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="CSV, TSV, XLSX, or XLSM file to profile")
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS, help="Maximum logical CSV/TSV data rows")
    parser.add_argument(
        "--max-xlsx-rows", type=int, default=DEFAULT_MAX_XLSX_ROWS_PER_SHEET,
        help="Maximum worksheet rows to inspect per XLSX/XLSM sheet",
    )
    parser.add_argument(
        "--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES,
        help="Refuse content parsing and hashing above this preflight file-size limit",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Atomically write JSON to a regular file; input aliases are refused",
    )
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.file.is_file():
        print(f"error: file does not exist: {args.file}", file=sys.stderr)
        return 2
    if args.output:
        try:
            validate_output_path(args.output, [args.file])
        except OutputPathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if min(args.max_rows, args.max_xlsx_rows, args.max_input_bytes) < 1:
        print("error: resource-limit arguments must be at least 1", file=sys.stderr)
        return 2
    suffix = args.file.suffix.lower()
    if suffix not in {".csv", ".tsv", ".xlsx", ".xlsm"}:
        print("error: supported formats are .csv, .tsv, .xlsx, and .xlsm", file=sys.stderr)
        return 2

    size = args.file.stat().st_size
    preflight = {
        "input_bytes": size,
        "max_input_bytes": args.max_input_bytes,
        "within_input_byte_limit": size <= args.max_input_bytes,
    }
    if size > args.max_input_bytes:
        profile: dict[str, Any] = {
            "kind": "delimited" if suffix in {".csv", ".tsv"} else "xlsx-package",
            "status": "skipped_preflight_resource_limit",
            "profile_complete": False,
            "warnings": [
                f"Input is {size} bytes, above the {args.max_input_bytes}-byte limit; content parsing and hashing were skipped."
            ],
        }
        file_hash: str | None = None
        hash_status = "not_computed_resource_limit"
    else:
        try:
            profile = (
                profile_delimited(args.file, args.max_rows)
                if suffix in {".csv", ".tsv"}
                else profile_xlsx(args.file, args.max_xlsx_rows)
            )
            file_hash = sha256(args.file)
            hash_status = "computed_streaming"
        except (OSError, csv.Error, zipfile.BadZipFile) as exc:
            print(f"error: unable to profile {args.file}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
    report = {
        "path": str(args.file.resolve()),
        "bytes": size,
        "sha256": file_hash,
        "hash_status": hash_status,
        "modified": False,
        "preflight": preflight,
        "profile": profile,
        "limitations": [
            "Delimited records are streamed and bounded; values are summarized but not emitted.",
            "XLSX values are not profiled. Formulas are counted but never calculated, and cached values are not current evidence.",
            "Macros, workbook events, links, connections, embedded objects, and network access are never executed or refreshed.",
            "A full application open, controlled recalculation, reconciliation, and visual inspection remain separate checks.",
        ],
    }
    payload = json.dumps(report, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        try:
            validate_output_path(args.output, [args.file])
            atomic_write_text(args.output, payload, [args.file])
        except OutputPathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
