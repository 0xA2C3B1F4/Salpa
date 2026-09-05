#!/usr/bin/env python3
"""Check the private source allowlist or a generated public source tree."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from public_tree import PublicTreeError, repository_root, validate_export, validate_source


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("source", help="validate allowlisted files in this source repository")
    export_parser = subparsers.add_parser("export", help="validate a generated public tree")
    export_parser.add_argument("directory", type=Path)
    export_parser.add_argument(
        "--allow-dirty-provenance",
        action="store_true",
        help="accept an export created for local testing from an uncommitted tree",
    )
    args = parser.parse_args()

    try:
        if args.mode == "source":
            count = len(validate_source(repository_root(__file__)))
            print(f"public source policy passed for {count} files")
        else:
            count = validate_export(
                args.directory,
                require_clean_provenance=not args.allow_dirty_provenance,
            )
            print(f"public export passed for {count} files")
    except (PublicTreeError, OSError, subprocess.CalledProcessError) as error:
        print(f"public tree check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
