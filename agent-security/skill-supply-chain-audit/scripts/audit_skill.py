#!/usr/bin/env python3
"""Create a bounded static inventory of an agent skill or archive.

Target code is never executed and archive members are never extracted. Findings
are evidence and heuristics for manual review, not malware verdicts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import tempfile
from typing import Any, Iterable
import zipfile


MAX_TEXT_BYTES = 1_000_000
MAX_ARCHIVE_CONTAINER_BYTES = 500_000_000
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_MEMBER_RECORDS = 5_000
MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES = 100_000_000
MAX_ARCHIVE_MEMBER_BYTES = 250_000_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1_000_000_000
MAX_ARCHIVE_RATIO = 100.0
TEXT_EXTENSIONS = {
    ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh",
    ".bash", ".zsh", ".ps1", ".rb", ".go", ".rs", ".java", ".xml",
    ".html", ".css", ".sql", ".csv",
}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile",
    "pipfile.lock", "cargo.toml", "cargo.lock", "go.mod", "go.sum",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".dylib", ".so", ".bin", ".class", ".jar", ".wasm",
    ".dmg", ".pkg", ".deb", ".rpm",
}
PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("SC001", "high", "Potential destructive or privileged shell behavior", re.compile(
        r"\b(?:sudo|launchctl|systemctl|crontab)\b|\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b|\b(?:mkfs|shutdown|reboot)\b",
        re.I,
    )),
    ("SC002", "high", "Remote content may be piped to an interpreter", re.compile(
        r"(?:curl|wget)[^\n|]{0,300}\|\s*(?:sh|bash|zsh|python(?:3)?|node)\b",
        re.I,
    )),
    ("SC003", "medium", "Dynamic execution or subprocess capability", re.compile(
        r"\b(?:eval|exec)\s*\(|\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen)\s*\(|\bchild_process\b|\b(?:spawn|execFile)\s*\(",
        re.I,
    )),
    ("SC004", "medium", "Network client or outbound request capability", re.compile(
        r"\b(?:requests\.(?:get|post|put|patch|delete)|urllib\.request|httpx\.|fetch\s*\(|axios\.|curl\s|wget\s)",
        re.I,
    )),
    ("SC005", "medium", "Credential or environment access requires review", re.compile(
        r"(?:\.env\b|os\.environ|process\.env|keychain|credentials?|api[_-]?key|access[_-]?token|secret[_-]?key)",
        re.I,
    )),
    ("SC006", "high", "Instruction may attempt authority or reporting bypass", re.compile(
        r"(?:ignore|override|bypass)\s+(?:all\s+)?(?:previous|prior|system|developer|safety|approval)\s+(?:instructions?|rules?|checks?)|(?:do not|don't|never)\s+(?:tell|report|mention|disclose)\s+(?:the\s+)?user",
        re.I,
    )),
    ("SC007", "medium", "Broad or sensitive filesystem path requires review", re.compile(
        r"(?:/etc/|/var/|/Users/|/home/|~/(?:\.ssh|\.aws|\.config)|\$HOME|\bHOME\b)",
        re.I,
    )),
]
URL_RE = re.compile(r"https?://[^\s<>'\"`\])}]+", re.I)


class OutputPathError(Exception):
    """Raised when a report destination cannot be used without risking evidence."""


def lexical_path(path: Path) -> Path:
    """Return an absolute normalized path without requiring the leaf to exist."""
    return Path(os.path.abspath(os.path.normpath(os.fspath(path))))


def resolved_path(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise OutputPathError(f"cannot resolve path safely: {path}: {exc}") from exc


def is_within(candidate: Path, directory: Path) -> bool:
    return candidate == directory or directory in candidate.parents


def validate_output_path(
    output: Path,
    inputs: Iterable[Path],
    protected_directories: Iterable[Path] = (),
) -> Path:
    """Fail closed when an output could overwrite or mutate audit evidence."""
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

    for directory in protected_directories:
        directory_lexical = lexical_path(directory)
        directory_resolved = resolved_path(directory)
        if is_within(output_lexical, directory_lexical) or is_within(output_resolved, directory_resolved):
            raise OutputPathError(
                f"output must be outside the audited directory: {directory}"
            )

    parent = output_lexical.parent
    if not parent.exists():
        raise OutputPathError(f"output directory does not exist: {parent}")
    if not parent.is_dir():
        raise OutputPathError(f"output parent is not a directory: {parent}")
    return output_resolved


def atomic_write_text(
    output: Path,
    payload: str,
    inputs: Iterable[Path],
    protected_directories: Iterable[Path] = (),
) -> None:
    """Atomically replace a validated regular report file via a sibling temp."""
    input_paths = tuple(inputs)
    protected_paths = tuple(protected_directories)
    destination = validate_output_path(output, input_paths, protected_paths)
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
        destination = validate_output_path(output, input_paths, protected_paths)
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(records: list[dict[str, Any]]) -> str:
    canonical = json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_manifest(files: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    keys = ("path", "type", "bytes", "sha256", "executable", "target")
    records = [
        {key: item[key] for key in keys if key in item}
        for item in sorted(files, key=lambda value: (value.get("path", ""), value.get("type", "")))
    ]
    return records, canonical_hash(records)


def add_finding(
    findings: list[dict[str, Any]], finding_id: str, severity: str, title: str,
    file: str, evidence: str, *, confidence: str = "high", line: int | None = None,
    claim_status: str = "observed",
) -> None:
    finding: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "confidence": confidence,
        "claim_status": claim_status,
        "file": file,
        "evidence": evidence,
        "title": title,
    }
    if line is not None:
        finding["line"] = line
    findings.append(finding)


def relative_label(path: Path, root: Path) -> str:
    if root.is_file() or root.is_symlink():
        return path.name
    return path.relative_to(root).as_posix()


def iter_entries(root: Path) -> Iterable[Path]:
    if root.is_file() or root.is_symlink():
        yield root
        return
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        current_path = Path(current)
        for name in sorted(dirs + files):
            yield current_path / name


def looks_text(path: Path, sample: bytes) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in MANIFEST_NAMES:
        return True
    if b"\x00" in sample:
        return False
    if not sample:
        return True
    printable = sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in sample)
    return printable / len(sample) > 0.85


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end < 0:
        return {}
    result: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" not in line or line[:1].isspace():
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip().strip("'\"")
    return result


def archive_path_issue(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    if "\x00" in normalized:
        return "NUL byte in member name"
    path = PurePosixPath(normalized)
    if path.is_absolute() or normalized.startswith("//") or re.match(r"^[A-Za-z]:/", normalized):
        return "absolute member path"
    if ".." in path.parts:
        return "parent-traversal member path"
    return None


def safe_archive_member_record(
    name: str, entry_type: str, size: int, compressed_size: int | None = None,
    link_target: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {"path": name, "type": entry_type, "bytes": size}
    if compressed_size is not None:
        record["compressed_bytes"] = compressed_size
        record["expansion_ratio"] = round(size / max(compressed_size, 1), 2)
    if link_target:
        record["link_target"] = link_target
    return record


def zip_directory_preflight(path: Path) -> tuple[int, int]:
    """Read the bounded EOCD trailer before zipfile allocates the directory."""
    with path.open("rb") as handle:
        size = path.stat().st_size
        tail_size = min(size, 65_557)
        handle.seek(size - tail_size)
        tail = handle.read(tail_size)
    signature = b"PK\x05\x06"
    position = len(tail) - 22
    while position >= 0:
        if tail[position:position + 4] == signature:
            fields = struct.unpack_from("<4s4H2LH", tail, position)
            comment_length = fields[7]
            if position + 22 + comment_length == len(tail):
                disk_number, central_disk = fields[1], fields[2]
                entries_on_disk, total_entries = fields[3], fields[4]
                central_bytes = fields[5]
                if disk_number or central_disk or entries_on_disk != total_entries:
                    raise ValueError("multi-disk ZIP archives are not supported for bounded inspection")
                if total_entries == 0xFFFF or central_bytes == 0xFFFFFFFF:
                    raise ValueError("ZIP64 central-directory limits could not be established without deeper parsing")
                return total_entries, central_bytes
        position -= 1
    raise ValueError("valid ZIP end-of-central-directory record was not found")


def inspect_zip(path: Path, label: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        declared_members, central_directory_bytes = zip_directory_preflight(path)
    except (OSError, ValueError, struct.error) as exc:
        add_finding(findings, "SC-ARCHIVE-PREFLIGHT", "high", "ZIP preflight could not establish safe bounds",
                    label, f"{type(exc).__name__}: {exc}")
        return {
            "path": label,
            "format": "zip",
            "inspection_method": "bounded EOCD preflight only; members not read or extracted",
            "inspection_complete": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    if declared_members > MAX_ARCHIVE_MEMBERS or central_directory_bytes > MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
        add_finding(findings, "SC-ARCHIVE-DIRECTORY-LIMIT", "high", "ZIP central directory exceeds inspection limits",
                    label, f"members={declared_members}, central_directory_bytes={central_directory_bytes}")
        return {
            "path": label,
            "format": "zip",
            "inspection_method": "bounded EOCD preflight only; members not read or extracted",
            "inspection_complete": False,
            "declared_members": declared_members,
            "central_directory_bytes": central_directory_bytes,
            "reason": "central-directory resource limit exceeded",
        }
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        selected = infos[:MAX_ARCHIVE_MEMBERS]
        inventory: list[dict[str, Any]] = []
        canonical_records: list[dict[str, Any]] = []
        total_uncompressed = 0
        total_compressed = 0
        risky_members = 0
        for info in selected:
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode) if mode else 0
            if info.is_dir() or file_type == stat.S_IFDIR:
                entry_type = "directory"
            elif file_type == stat.S_IFLNK:
                entry_type = "symlink"
            elif file_type not in (0, stat.S_IFREG):
                entry_type = "special"
            else:
                entry_type = "file"
            record = safe_archive_member_record(
                info.filename, entry_type, info.file_size, info.compress_size
            )
            canonical_records.append(record)
            if len(inventory) < MAX_ARCHIVE_MEMBER_RECORDS:
                inventory.append(record)
            total_uncompressed += info.file_size
            total_compressed += info.compress_size
            issue = archive_path_issue(info.filename)
            if issue:
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-PATH", "high", issue.capitalize(), label,
                            f"archive member {info.filename!r}")
            if entry_type == "symlink":
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-SYMLINK", "high", "Archive contains a symlink",
                            label, f"archive member {info.filename!r}")
            elif entry_type == "special":
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-SPECIAL", "high", "Archive contains a special entry",
                            label, f"archive member {info.filename!r}, mode={oct(mode)}")
            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-MEMBER-SIZE", "high", "Archive member exceeds size limit",
                            label, f"{info.filename!r}: {info.file_size} bytes")
            if info.file_size > 1_000_000 and ratio > MAX_ARCHIVE_RATIO:
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-RATIO", "high", "Archive member has excessive expansion ratio",
                            label, f"{info.filename!r}: {ratio:.2f}:1")

        complete = len(infos) <= MAX_ARCHIVE_MEMBERS
        if not complete:
            add_finding(findings, "SC-ARCHIVE-MEMBER-LIMIT", "high", "Archive member limit reached",
                        label, f"{len(infos)} declared members; inspected first {MAX_ARCHIVE_MEMBERS}")
        overall_ratio = total_uncompressed / max(total_compressed, 1)
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            add_finding(findings, "SC-ARCHIVE-TOTAL-SIZE", "high", "Archive declared expansion exceeds limit",
                        label, f"{total_uncompressed} bytes across inspected members")
        if total_uncompressed > 10_000_000 and overall_ratio > MAX_ARCHIVE_RATIO:
            add_finding(findings, "SC-ARCHIVE-TOTAL-RATIO", "high", "Archive has excessive aggregate expansion ratio",
                        label, f"{overall_ratio:.2f}:1 across inspected members")
        return {
            "path": label,
            "format": "zip",
            "inspection_method": "central-directory metadata only; members not read or extracted",
            "inspection_complete": complete,
            "declared_members": len(infos),
            "central_directory_bytes": central_directory_bytes,
            "members_inspected": len(selected),
            "member_inventory": inventory,
            "member_inventory_truncated": len(canonical_records) > len(inventory),
            "canonical_member_manifest_sha256": canonical_hash(sorted(canonical_records, key=lambda item: item["path"])),
            "declared_uncompressed_bytes_inspected": total_uncompressed,
            "declared_compressed_bytes_inspected": total_compressed,
            "aggregate_expansion_ratio": round(overall_ratio, 2),
            "risky_member_observations": risky_members,
        }


def tar_entry_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    if member.isfile():
        return "file"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "special"


def inspect_tar(path: Path, label: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    inventory: list[dict[str, Any]] = []
    canonical_records: list[dict[str, Any]] = []
    total_uncompressed = 0
    risky_members = 0
    complete = True
    with tarfile.open(path, mode="r:*") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_ARCHIVE_MEMBERS:
                complete = False
                add_finding(findings, "SC-ARCHIVE-MEMBER-LIMIT", "high", "Archive member limit reached",
                            label, f"inspection stopped after {MAX_ARCHIVE_MEMBERS} members")
                break
            entry_type = tar_entry_type(member)
            link_target = member.linkname if entry_type in {"symlink", "hardlink"} else None
            record = safe_archive_member_record(member.name, entry_type, member.size, link_target=link_target)
            canonical_records.append(record)
            if len(inventory) < MAX_ARCHIVE_MEMBER_RECORDS:
                inventory.append(record)
            total_uncompressed += member.size
            issue = archive_path_issue(member.name)
            if issue:
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-PATH", "high", issue.capitalize(), label,
                            f"archive member {member.name!r}")
            if entry_type in {"symlink", "hardlink"}:
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-LINK", "high", f"Archive contains a {entry_type}",
                            label, f"{member.name!r} -> {member.linkname!r}")
                target_issue = archive_path_issue(member.linkname)
                if target_issue:
                    add_finding(findings, "SC-ARCHIVE-LINK-TARGET", "high", "Archive link target is unsafe",
                                label, f"{member.name!r} -> {member.linkname!r}: {target_issue}")
            elif entry_type == "special":
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-SPECIAL", "high", "Archive contains a special entry",
                            label, f"archive member {member.name!r}, type={member.type!r}")
            if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                risky_members += 1
                add_finding(findings, "SC-ARCHIVE-MEMBER-SIZE", "high", "Archive member exceeds size limit",
                            label, f"{member.name!r}: {member.size} bytes")
            if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                complete = False
                add_finding(findings, "SC-ARCHIVE-TOTAL-SIZE", "high", "Archive declared expansion exceeds limit",
                            label, f"inspection stopped after {total_uncompressed} declared bytes")
                break
    outer_bytes = path.stat().st_size
    overall_ratio = total_uncompressed / max(outer_bytes, 1)
    if total_uncompressed > 10_000_000 and overall_ratio > MAX_ARCHIVE_RATIO:
        add_finding(findings, "SC-ARCHIVE-TOTAL-RATIO", "high", "Archive has excessive aggregate expansion ratio",
                    label, f"{overall_ratio:.2f}:1 for inspected headers")
    return {
        "path": label,
        "format": "tar",
        "inspection_method": "tar header metadata only; members not extracted",
        "inspection_complete": complete,
        "members_inspected": len(canonical_records),
        "member_inventory": inventory,
        "member_inventory_truncated": len(canonical_records) > len(inventory),
        "canonical_member_manifest_sha256": canonical_hash(sorted(canonical_records, key=lambda item: item["path"])),
        "declared_uncompressed_bytes_inspected": total_uncompressed,
        "container_bytes": outer_bytes,
        "aggregate_expansion_ratio": round(overall_ratio, 2),
        "risky_member_observations": risky_members,
    }


def inspect_archive(path: Path, label: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_ARCHIVE_CONTAINER_BYTES:
        add_finding(findings, "SC-ARCHIVE-CONTAINER-LIMIT", "high", "Archive metadata inspection skipped at size limit",
                    label, f"{size} bytes exceeds {MAX_ARCHIVE_CONTAINER_BYTES}")
        return {
            "path": label,
            "format": "unknown",
            "inspection_method": "skipped before archive parsing",
            "inspection_complete": False,
            "reason": "container byte limit exceeded",
        }
    try:
        if zipfile.is_zipfile(path):
            return inspect_zip(path, label, findings)
        if tarfile.is_tarfile(path):
            return inspect_tar(path, label, findings)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        add_finding(findings, "SC-ARCHIVE-READ", "high", "Archive metadata could not be inspected",
                    label, f"{type(exc).__name__}: {exc}")
        return {
            "path": label,
            "format": "unreadable",
            "inspection_method": "metadata parse attempted; members not extracted",
            "inspection_complete": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    add_finding(findings, "SC-ARCHIVE-UNSUPPORTED", "medium", "Archive format needs a safe metadata inspector",
                label, path.suffix.lower() or "unknown extension")
    return {
        "path": label,
        "format": "unsupported-or-not-recognized",
        "inspection_method": "no member inspection performed",
        "inspection_complete": False,
    }


def scan(root: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    archives: list[dict[str, Any]] = []
    content_review_queue: list[dict[str, Any]] = []
    urls: set[str] = set()
    manifests: list[str] = []
    total_bytes = 0
    regular_count = 0
    text_files_scanned = 0
    skill_frontmatter: dict[str, str] = {}

    for entry in iter_entries(root):
        label = relative_label(entry, root)
        try:
            mode = entry.lstat().st_mode
        except OSError as exc:
            add_finding(findings, "SC-READ", "medium", "Entry could not be inspected",
                        label, str(exc))
            continue

        if stat.S_ISLNK(mode):
            target = os.readlink(entry)
            escapes = Path(target).is_absolute()
            if not escapes:
                try:
                    resolved = (entry.parent / target).resolve()
                    escapes = root.is_dir() and root.resolve() not in (resolved, *resolved.parents)
                except OSError:
                    escapes = True
            files.append({"path": label, "type": "symlink", "target": target})
            add_finding(findings, "SC-SYMLINK", "high" if escapes else "low",
                        "Symlink escapes package root" if escapes else "Package contains a symlink",
                        label, target)
            continue
        if stat.S_ISDIR(mode):
            files.append({"path": label, "type": "directory"})
            continue
        if not stat.S_ISREG(mode):
            files.append({"path": label, "type": "special"})
            add_finding(findings, "SC-SPECIAL", "high", "Package contains a special filesystem entry",
                        label, "non-regular, non-directory entry")
            continue

        regular_count += 1
        size = entry.stat().st_size
        total_bytes += size
        executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        suffix = entry.suffix.lower()
        digest = sha256_file(entry)
        record = {
            "path": label,
            "type": "file",
            "bytes": size,
            "sha256": digest,
            "executable": executable,
        }
        files.append(record)
        if entry.name.lower() in MANIFEST_NAMES:
            manifests.append(label)
        if suffix in ARCHIVE_EXTENSIONS:
            archives.append(inspect_archive(entry, label, findings))
        if suffix in BINARY_EXTENSIONS:
            add_finding(findings, "SC-BINARY", "medium", "Opaque executable or binary artifact",
                        label, suffix)
        if executable:
            add_finding(findings, "SC-EXEC", "low", "Executable file requires manual review",
                        label, "executable permission bit set")

        try:
            with entry.open("rb") as handle:
                sample = handle.read(8192)
        except OSError as exc:
            add_finding(findings, "SC-READ", "medium", "File content could not be sampled",
                        label, str(exc))
            continue
        is_text = looks_text(entry, sample)
        if size > MAX_TEXT_BYTES:
            content_review_queue.append({
                "path": label,
                "bytes": size,
                "sha256": digest,
                "appears_text": is_text,
                "reason": f"content pattern scan limited to files at or below {MAX_TEXT_BYTES} bytes",
                "required_action": "perform bounded read-only chunked/manual review or record why opaque content is accepted",
                "status": "unresolved",
            })
            add_finding(findings, "SC-CONTENT-SKIPPED", "medium",
                        "File content requires separate bounded review", label,
                        f"{size} bytes; SHA-256 {digest}")
            continue
        if not is_text:
            continue
        try:
            raw = entry.read_bytes()
        except OSError as exc:
            add_finding(findings, "SC-READ", "medium", "Text file could not be read",
                        label, str(exc))
            continue
        text_files_scanned += 1
        text = raw.decode("utf-8", errors="replace")
        urls.update(URL_RE.findall(text))
        if entry.name == "SKILL.md":
            skill_frontmatter = parse_frontmatter(text)
        for rule_id, severity, title, pattern in PATTERNS:
            for match in list(pattern.finditer(text))[:10]:
                line = text.count("\n", 0, match.start()) + 1
                snippet = " ".join(match.group(0).split())[:240]
                add_finding(findings, rule_id, severity, title, label, snippet,
                            confidence="low", line=line, claim_status="observed")

    if root.is_dir() and skill_frontmatter:
        declared_name = skill_frontmatter.get("name", "")
        if declared_name and declared_name != root.name:
            add_finding(findings, "SC-META-NAME", "medium", "Skill name does not match folder",
                        "SKILL.md", f"name={declared_name!r}, folder={root.name!r}")
        extra = sorted(set(skill_frontmatter) - {"name", "description"})
        if extra:
            add_finding(findings, "SC-META-EXTRA", "low", "Frontmatter contains non-standard keys",
                        "SKILL.md", ", ".join(extra))
        description = skill_frontmatter.get("description", "")
        if "use when" not in description.lower():
            add_finding(findings, "SC-META-TRIGGER", "low", "Activation boundary is unclear",
                        "SKILL.md", "description lacks an explicit 'Use when' trigger")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    findings.sort(key=lambda item: (severity_order.get(item["severity"], 99), item.get("file", ""), item.get("line", 0)))
    manifest_records, manifest_digest = canonical_manifest(files)
    archive_incomplete = any(not item.get("inspection_complete", False) for item in archives)
    return {
        "target": str(root.resolve()),
        "method": "read-only static heuristics and non-extracting archive metadata inspection; target code was not executed",
        "claim_status_vocabulary": ["observed", "inferred", "unknown"],
        "claims": [
            {"claim": "reported filesystem hashes and metadata", "status": "observed"},
            {"claim": "risk implications of heuristic pattern matches", "status": "inferred"},
            {"claim": "runtime safety and absence of malicious behavior", "status": "unknown"},
        ],
        "limits": [
            f"Content pattern scanning is limited to files at or below {MAX_TEXT_BYTES} bytes.",
            f"Archive metadata inspection stops at {MAX_ARCHIVE_MEMBERS} members, a {MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES}-byte ZIP directory, or {MAX_ARCHIVE_UNCOMPRESSED_BYTES} declared bytes.",
            "Archive members are not extracted or executed; nested member contents are not recursively scanned.",
            "Pattern matches require manual validation and may be benign.",
            "No malware-absence or runtime-safety claim is made.",
        ],
        "summary": {
            "regular_files": regular_count,
            "total_bytes": total_bytes,
            "text_files_pattern_scanned": text_files_scanned,
            "content_review_queue": len(content_review_queue),
            "archives": len(archives),
            "archives_with_incomplete_member_inspection": sum(
                not item.get("inspection_complete", False) for item in archives
            ),
            "findings": len(findings),
            "manifests": len(manifests),
            "urls": len(urls),
        },
        "coverage": {
            "content_pattern_scan_complete": not content_review_queue,
            "archive_metadata_inspection_complete": not archive_incomplete,
            "unresolved_content_review_paths": [item["path"] for item in content_review_queue],
        },
        "canonical_manifest_algorithm": "SHA-256 of sorted UTF-8 canonical JSON records (path/type/bytes/hash/executable/target)",
        "canonical_manifest_sha256": manifest_digest,
        "canonical_manifest_entries": len(manifest_records),
        "skill_frontmatter": skill_frontmatter,
        "manifests": sorted(manifests),
        "urls": sorted(urls),
        "files": files,
        "archives": archives,
        "content_review_queue": content_review_queue,
        "findings": findings,
    }


def file_hashes(report: dict[str, Any]) -> dict[str, str]:
    return {
        item["path"]: item["sha256"]
        for item in report["files"]
        if item.get("type") == "file" and "sha256" in item
    }


def compare(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    new = file_hashes(current)
    old = file_hashes(baseline)
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(path for path in set(new) & set(old) if new[path] != old[path]),
        "unchanged": sorted(path for path in set(new) & set(old) if new[path] == old[path]),
        "canonical_manifest_changed": current["canonical_manifest_sha256"] != baseline["canonical_manifest_sha256"],
        "current_canonical_manifest_sha256": current["canonical_manifest_sha256"],
        "baseline_canonical_manifest_sha256": baseline["canonical_manifest_sha256"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="File or directory to inspect without executing")
    parser.add_argument("--baseline", type=Path, help="Known-good file or directory for canonical/hash comparison")
    parser.add_argument(
        "--output", type=Path,
        help="Atomically write JSON outside audited directories; input aliases are refused",
    )
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.target.exists() and not args.target.is_symlink():
        print(f"error: target does not exist: {args.target}", file=sys.stderr)
        return 2
    if args.baseline and not args.baseline.exists() and not args.baseline.is_symlink():
        print(f"error: baseline does not exist: {args.baseline}", file=sys.stderr)
        return 2
    inputs = [args.target] + ([args.baseline] if args.baseline else [])
    protected_directories = [path for path in inputs if path.is_dir()]
    if args.output:
        try:
            validate_output_path(args.output, inputs, protected_directories)
        except OutputPathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    report = scan(args.target)
    if args.baseline:
        baseline_report = scan(args.baseline)
        report["baseline"] = str(args.baseline.resolve())
        report["comparison"] = compare(report, baseline_report)
    payload = json.dumps(report, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        try:
            validate_output_path(args.output, inputs, protected_directories)
            atomic_write_text(args.output, payload, inputs, protected_directories)
        except OutputPathError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
