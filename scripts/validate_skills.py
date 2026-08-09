#!/usr/bin/env python3
"""Validate the repository's Agent Skills catalog without third-party packages."""

from __future__ import annotations

import ast
import hashlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ACTIVATION_RE = re.compile(r"\b(?:use when|use this skill when|use for|use this skill for)\b", re.I)
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def scalar(frontmatter: str, field: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*(.+?)\s*$", frontmatter)
    if not match:
        return None
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value


def split_skill(path: Path) -> tuple[str, str]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", text, re.S)
    if not match:
        raise ValueError("missing YAML frontmatter delimited by ---")
    return match.group(1), match.group(2)


def without_fenced_code(markdown: str) -> str:
    kept: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        marker = line.lstrip()
        if fence is None and (marker.startswith("```") or marker.startswith("~~~")):
            fence = marker[:3]
            continue
        if fence is not None:
            if marker.startswith(fence):
                fence = None
            continue
        kept.append(line)
    return "\n".join(kept)


def validate_agent_metadata(skill_dir: Path, name: str, errors: list[str]) -> None:
    config = skill_dir / "agents" / "openai.yaml"
    if not config.exists():
        return
    text = config.read_text(encoding="utf-8")
    display_name = scalar(text, "display_name")
    default_prompt = scalar(text, "default_prompt")
    short_description = scalar(text, "short_description")
    if not display_name:
        errors.append(f"{config.relative_to(ROOT)}: display_name is required")
    if not default_prompt or f"${name}" not in default_prompt:
        errors.append(f"{config.relative_to(ROOT)}: default_prompt must mention ${name}")
    if not short_description or not 25 <= len(short_description) <= 64:
        errors.append(
            f"{config.relative_to(ROOT)}: short_description must contain 25-64 characters"
        )


def validate_python_scripts(skill_dir: Path, errors: list[str]) -> None:
    for script in sorted((skill_dir / "scripts").glob("*.py")):
        try:
            ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"{script.relative_to(ROOT)}: Python syntax/read error: {exc}")


def validate_local_links(path: Path, body: str, errors: list[str]) -> None:
    for target in LINK_RE.findall(without_fenced_code(body)):
        target = target.strip().strip("<>").split()[0]
        if not target or target.startswith(("http://", "https://", "mailto:", "#", "/")):
            continue
        clean = target.split("#", 1)[0].split("?", 1)[0]
        if not clean:
            continue
        resolved = (path.parent / clean).resolve()
        if not resolved.is_relative_to(ROOT) or not resolved.exists():
            errors.append(f"{path.relative_to(ROOT)}: broken local link {target!r}")


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    skills = sorted(ROOT.glob("*/*/SKILL.md"))
    names: dict[str, Path] = {}
    hashes: dict[str, Path] = {}

    if not skills:
        errors.append("No category/skill/SKILL.md files found")

    for path in skills:
        rel = path.relative_to(ROOT)
        try:
            frontmatter, body = split_skill(path)
        except ValueError as exc:
            errors.append(f"{rel}: {exc}")
            continue

        name = scalar(frontmatter, "name")
        description = scalar(frontmatter, "description")
        expected = path.parent.name

        if not name:
            errors.append(f"{rel}: missing name")
        else:
            if not NAME_RE.fullmatch(name) or len(name) > 64:
                errors.append(f"{rel}: invalid skill name {name!r}")
            if name != expected:
                errors.append(f"{rel}: name {name!r} does not match directory {expected!r}")
            if name in names:
                errors.append(f"{rel}: duplicate name also used by {names[name].relative_to(ROOT)}")
            names[name] = path

        if not description:
            errors.append(f"{rel}: missing description")
        else:
            if len(description) > 1024:
                errors.append(f"{rel}: description exceeds 1024 characters")
            if not ACTIVATION_RE.search(description):
                errors.append(f"{rel}: description must contain an explicit 'Use when' trigger")

        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count > 500:
            errors.append(f"{rel}: {line_count} lines exceeds the 500-line limit")
        if not re.search(r"(?m)^# [^#]", body):
            errors.append(f"{rel}: missing H1 title")
        if not re.search(r"(?im)^## (?:workflow|procedure|process)\s*$", body):
            errors.append(f"{rel}: missing Workflow, Procedure, or Process section")
        if re.search(r"(?im)(?:^|\s)(?:TODO|TBD)\s*(?::|$)|\bREPLACE_ME\b", body):
            errors.append(f"{rel}: unresolved placeholder")

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in hashes:
            errors.append(f"{rel}: exact duplicate of {hashes[digest].relative_to(ROOT)}")
        hashes[digest] = path

        validate_local_links(path, body, errors)
        validate_python_scripts(path.parent, errors)
        if name:
            validate_agent_metadata(path.parent, name, errors)

        risky = re.search(
            r"\b(?:rm\s+-rf|git\s+reset\s+--hard|terraform\s+destroy|DROP\s+(?:TABLE|DATABASE))\b",
            body,
            re.I,
        )
        if risky and not re.search(r"\b(?:confirm|approval|authorized|rollback|validate)\b", body, re.I):
            warnings.append(f"{rel}: destructive example lacks an obvious safeguard")

    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
    indexed = {
        match.rstrip("/")
        for match in re.findall(r"\]\(\./([a-z0-9-]+/[a-z0-9-]+)/?\)", readme)
    }
    actual = {str(path.parent.relative_to(ROOT)) for path in skills}
    for missing in sorted(actual - indexed):
        errors.append(f"README.md: missing skill index entry {missing}")
    for stale in sorted(indexed - actual):
        errors.append(f"README.md: stale skill index entry {stale}")

    count_match = re.search(r"<!--\s*skill-count:\s*(\d+)\s*-->", readme)
    if not count_match:
        errors.append("README.md: missing <!-- skill-count: N --> marker")
    elif int(count_match.group(1)) != len(skills):
        errors.append(
            f"README.md: marker says {count_match.group(1)} skills but found {len(skills)}"
        )

    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}")

    if errors:
        print(f"\nValidation failed: {len(errors)} error(s), {len(warnings)} warning(s).")
        return 1
    print(f"Validated {len(skills)} skills across {len({p.parent.parent.name for p in skills})} categories.")
    if warnings:
        print(f"Completed with {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
