"""Shared host-side utilities. Device policy and manifest schemas stay with callers."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def git_output(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_within(child: Path, parent: Path) -> bool:
    """Compare paths as supplied; callers resolve aliases before enforcing policy."""
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def parse_sdkconfig(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line.removeprefix("# ").removesuffix(" is not set")] = "n"
    return values
