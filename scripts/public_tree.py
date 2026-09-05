#!/usr/bin/env python3
"""Validation shared by the private source tree and generated public tree."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

from source_references import missing_references

POLICY_PATH = PurePosixPath("policy/public-files.txt")
PROVENANCE_PATH = PurePosixPath("source-export.json")

FORBIDDEN_NAMES = {".DS_Store", "AGENTS.md"}
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".crt",
    ".der",
    ".elf",
    ".env",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".uf2",
}

CONTENT_RULES = (
    (
        "private-key PEM data",
        re.compile(rb"-----BEGIN " + rb"(?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    ("GitHub token", re.compile(rb"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}")),
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("OpenAI-style secret", re.compile(rb"sk-[A-Za-z0-9_-]{20,}")),
    ("macOS user path", re.compile(("/" + "Users/").encode() + rb"[^/\s]+/")),
    ("macOS volume path", re.compile(("/" + "Volumes/").encode())),
    ("Apple private relay address", re.compile(rb"[A-Za-z0-9._%+-]+@privaterelay\.appleid\.com")),
)


class PublicTreeError(RuntimeError):
    """A public-tree policy violation."""


def repository_root(script_file: str) -> Path:
    return Path(script_file).resolve().parent.parent


def load_public_files(root: Path) -> list[PurePosixPath]:
    policy_file = root / POLICY_PATH
    try:
        lines = policy_file.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise PublicTreeError(f"cannot read {POLICY_PATH}: {error}") from error

    entries: list[PurePosixPath] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        path = PurePosixPath(line)
        if path.is_absolute() or ".." in path.parts or line != path.as_posix():
            raise PublicTreeError(
                f"invalid path at {POLICY_PATH}:{line_number}: {raw_line!r}"
            )
        entries.append(path)

    if entries != sorted(entries, key=lambda path: path.as_posix()):
        raise PublicTreeError(f"{POLICY_PATH} entries must be sorted")
    if len(entries) != len(set(entries)):
        raise PublicTreeError(f"{POLICY_PATH} contains duplicate entries")
    for required in (PurePosixPath("LICENSE"), POLICY_PATH, PurePosixPath(".github/SECURITY.md")):
        if required not in entries:
            raise PublicTreeError(f"required public file is missing from policy: {required}")
    return entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _check_path(path: PurePosixPath) -> None:
    if any(part in FORBIDDEN_NAMES for part in path.parts) or path.name.endswith("_handoff.md"):
        raise PublicTreeError(f"forbidden public path: {path}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise PublicTreeError(f"forbidden public file type: {path}")


def _check_content(root: Path, paths: list[PurePosixPath]) -> None:
    failures: list[str] = []
    for relative in paths:
        data = (root / relative).read_bytes()
        if b"\0" in data:
            failures.append(f"binary content: {relative}")
            continue
        for label, pattern in CONTENT_RULES:
            if pattern.search(data):
                failures.append(f"{label}: {relative}")
    if failures:
        raise PublicTreeError("public content check failed:\n  " + "\n  ".join(failures))


def validate_source(root: Path, require_tracked: bool = True) -> list[PurePosixPath]:
    root = root.resolve()
    public_files = load_public_files(root)
    tracked: set[str] = set()
    if require_tracked:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        tracked = {
            item.decode("utf-8") for item in result.stdout.split(b"\0") if item
        }

    for relative in public_files:
        _check_path(relative)
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise PublicTreeError(f"public source must be a regular file: {relative}")
        if require_tracked and relative.as_posix() not in tracked:
            raise PublicTreeError(f"public source is not tracked by Git: {relative}")

    _check_content(root, public_files)
    _check_references(root, public_files)
    return public_files


def _check_references(root: Path, paths: list[PurePosixPath]) -> None:
    failures = missing_references(root, paths)
    if failures:
        raise PublicTreeError("public references are incomplete:\n  " + "\n  ".join(failures))


def export_file_set(root: Path) -> set[PurePosixPath]:
    files: set[PurePosixPath] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise PublicTreeError(f"public export contains a symlink: {relative}")
        if path.is_file():
            files.add(PurePosixPath(relative.as_posix()))
    return files


def validate_export(root: Path, require_clean_provenance: bool = True) -> int:
    root = root.resolve()
    public_files = load_public_files(root)
    expected = set(public_files) | {PROVENANCE_PATH}
    actual = export_file_set(root)
    if actual != expected:
        missing = sorted(expected - actual, key=str)
        extra = sorted(actual - expected, key=str)
        details = []
        if missing:
            details.append("missing: " + ", ".join(map(str, missing)))
        if extra:
            details.append("extra: " + ", ".join(map(str, extra)))
        raise PublicTreeError("public export file set differs from policy; " + "; ".join(details))

    for relative in public_files:
        _check_path(relative)
    _check_content(root, [*public_files, PROVENANCE_PATH])

    _check_references(root, public_files)

    try:
        provenance = json.loads((root / PROVENANCE_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PublicTreeError(f"invalid {PROVENANCE_PATH}: {error}") from error

    if provenance.get("schema") != 1 or provenance.get("license") != "MIT":
        raise PublicTreeError(f"unsupported {PROVENANCE_PATH} schema or license")
    if require_clean_provenance and provenance.get("source_dirty") is not False:
        raise PublicTreeError("public release provenance must come from a clean source tree")
    for key in ("source_commit", "source_tree"):
        value = provenance.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise PublicTreeError(f"invalid provenance field: {key}")

    hashes = provenance.get("files")
    expected_paths = {path.as_posix() for path in public_files}
    if not isinstance(hashes, dict) or set(hashes) != expected_paths:
        raise PublicTreeError("provenance file list differs from public policy")
    for relative in public_files:
        expected_hash = hashes.get(relative.as_posix())
        actual_hash = sha256_file(root / relative)
        if expected_hash != actual_hash:
            raise PublicTreeError(f"SHA-256 mismatch: {relative}")
    return len(public_files)
