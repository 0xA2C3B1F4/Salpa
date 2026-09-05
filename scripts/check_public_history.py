#!/usr/bin/env python3
"""Reject forbidden paths and sensitive content anywhere in public Git history."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True

from public_tree import (
    CONTENT_RULES,
    FORBIDDEN_NAMES,
    FORBIDDEN_SUFFIXES,
    PublicTreeError,
    repository_root,
)


def git_bytes(root: Path, *args: str, input_data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_data,
        check=True,
        capture_output=True,
    ).stdout


def historical_blobs(root: Path) -> dict[str, set[str]]:
    commits = git_bytes(root, "rev-list", "--all").decode("ascii").splitlines()
    blobs: dict[str, set[str]] = {}
    for commit in commits:
        entries = git_bytes(root, "ls-tree", "-r", "-z", commit).split(b"\0")
        for entry in entries:
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            _mode, object_type, object_id = metadata.decode("ascii").split()
            if object_type != "blob":
                continue
            path = raw_path.decode("utf-8")
            blobs.setdefault(object_id, set()).add(path)
    return blobs


def validate_history(root: Path) -> int:
    failures: list[str] = []
    # Commits include author/committer metadata and messages. Annotated tags
    # have their own tagger and message, outside file blobs.
    objects = git_bytes(root, "rev-list", "--objects", "--all").splitlines()
    object_ids = [line.split(b" ", 1)[0] for line in objects]
    types = git_bytes(root, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                      input_data=b"\n".join(object_ids) + b"\n")
    for record in types.decode("ascii").splitlines():
        object_id, object_type = record.split()
        if object_type not in {"commit", "tag"}:
            continue
        data = git_bytes(root, "cat-file", object_type, object_id)
        for label, pattern in CONTENT_RULES:
            if pattern.search(data):
                failures.append(f"{label} in {object_type} metadata: {object_id}")
    blobs = historical_blobs(root)
    for object_id, paths in blobs.items():
        for raw_path in paths:
            path = PurePosixPath(raw_path)
            if any(part in FORBIDDEN_NAMES for part in path.parts) or path.name.endswith("_handoff.md"):
                failures.append(f"forbidden historical path: {raw_path}")
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                failures.append(f"forbidden historical file type: {raw_path}")

        data = git_bytes(root, "cat-file", "blob", object_id)
        if b"\0" in data:
            failures.append(f"binary historical blob: {', '.join(sorted(paths))}")
            continue
        for label, pattern in CONTENT_RULES:
            if pattern.search(data):
                failures.append(f"{label}: {', '.join(sorted(paths))}")

    if failures:
        raise PublicTreeError(
            "public Git history check failed:\n  " + "\n  ".join(sorted(set(failures)))
        )
    return len(blobs)


def main() -> int:
    try:
        count = validate_history(repository_root(__file__))
    except (PublicTreeError, OSError, subprocess.CalledProcessError, UnicodeDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"public Git history passed for {count} unique blobs and reachable commit/tag metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
