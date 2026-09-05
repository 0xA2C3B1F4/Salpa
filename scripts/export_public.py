#!/usr/bin/env python3
"""Create a manifest-bound public source tree from the private repository."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from public_tree import (
    PROVENANCE_PATH,
    PublicTreeError,
    repository_root,
    sha256_file,
    validate_export,
    validate_source,
)


def git_output(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="create a local test export with dirty provenance",
    )
    args = parser.parse_args()

    source = repository_root(__file__)
    destination = args.destination.expanduser().resolve()
    if is_within(destination, source):
        print("destination must be outside the development repository", file=sys.stderr)
        return 1
    if destination.exists() and any(destination.iterdir()):
        print("destination must not exist or must be empty", file=sys.stderr)
        return 1

    try:
        public_files = validate_source(source)
        status = git_output(source, "status", "--porcelain=v1", "--untracked-files=all")
        source_dirty = bool(status)
        if source_dirty and not args.allow_dirty:
            raise PublicTreeError("source tree is dirty; commit changes before public export")

        destination.mkdir(parents=True, exist_ok=True)
        for relative in public_files:
            source_file = source / relative
            destination_file = destination / relative
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination_file)

        provenance = {
            "schema": 1,
            "license": "MIT",
            "source_commit": git_output(source, "rev-parse", "HEAD"),
            "source_tree": git_output(source, "rev-parse", "HEAD^{tree}"),
            "source_dirty": source_dirty,
            "files": {
                relative.as_posix(): sha256_file(destination / relative)
                for relative in public_files
            },
        }
        (destination / PROVENANCE_PATH).write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        count = validate_export(destination, require_clean_provenance=not args.allow_dirty)
    except (PublicTreeError, OSError, subprocess.CalledProcessError) as error:
        print(f"public export failed: {error}", file=sys.stderr)
        return 1

    print(f"exported {count} files to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
