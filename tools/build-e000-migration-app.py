#!/usr/bin/env python3
"""Build the ESP32-S2 application for the reversible 0xE000 migration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import git_output, is_within, sha256_file


FEATURES = ["ctaphid-bringup", "fido-stack", "mcu-esp32s2"]
PARTITION_PROFILE = "e000-migration"
SECURITY_PROFILE = "wemos-s2-mini-e000-migration-test"
TARGET = "xtensa-esp32s2-none-elf"


class BuildError(RuntimeError):
    """The reversible migration application build gate was not met."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def command_output(path: Path, *args: str) -> str:
    return subprocess.run(
        list(args), cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a clean-tree ESP32-S2 application bound to partitions-e000.csv. "
            "USB identity values are read from the environment and never recorded."
        )
    )
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()

    root = repository_root()
    build_dir = args.build_dir.expanduser().resolve()
    required_environment = [
        "RISSO_KEY_USB_PID",
        "RISSO_KEY_USB_SERIAL",
        "RISSO_KEY_USB_VID",
    ]

    try:
        if is_within(build_dir, root):
            raise BuildError("build directory must stay outside the source repository")
        if build_dir.exists() and any(build_dir.iterdir()):
            raise BuildError("build directory must be new or empty")
        missing = [name for name in required_environment if not os.environ.get(name)]
        if missing:
            raise BuildError(f"missing required environment: {', '.join(missing)}")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("source tree must be clean before recording build evidence")

        build_dir.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "CARGO_TARGET_DIR": str(build_dir),
                "RISSO_KEY_MCU": "esp32s2",
                "RISSO_KEY_PARTITION_PROFILE": PARTITION_PROFILE,
            }
        )
        command = [
            str(root / "tools/cargo-esp"),
            "build",
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            ",".join(FEATURES),
            "--bin",
            "rissokey",
        ]
        subprocess.run(command, cwd=root, env=environment, check=True)

        artifact = build_dir / TARGET / "release/rissokey"
        if not artifact.is_file() or artifact.is_symlink():
            raise BuildError("missing regular Rust application ELF")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("application build modified the source tree")

        manifest = {
            "artifact": {
                "file": f"{TARGET}/release/rissokey",
                "sha256": sha256_file(artifact),
                "size": artifact.stat().st_size,
            },
            "build": {
                "command": [
                    "./tools/cargo-esp",
                    *command[1:],
                ],
                "environment_values_recorded": False,
                "features": FEATURES,
                "mcu": "esp32s2",
                "partition_profile": PARTITION_PROFILE,
                "required_environment": required_environment,
                "security_profile": SECURITY_PROFILE,
            },
            "build_only": True,
            "efuse_operations_performed": False,
            "flash_authorized": False,
            "generated_at": datetime.now(UTC).isoformat(),
            "kind": "rissokey-e000-migration-application",
            "schema": 1,
            "source": {
                "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
                "commit": git_output(root, "rev-parse", "HEAD"),
                "partition_table_sha256": sha256_file(root / "partitions-e000.csv"),
                "security_profiles_sha256": sha256_file(
                    root / "policy/security-profiles.json"
                ),
                "tree": git_output(root, "rev-parse", "HEAD^{tree}"),
            },
            "toolchain": {
                "cargo": command_output(root, "cargo", "-vV"),
                "rustc": command_output(root, "rustc", "-vV"),
            },
        }
        manifest_path = build_dir / "rissokey-e000-application-build.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"0xE000 migration application build failed: {error}", file=sys.stderr)
        return 1

    print(f"built 0xE000 migration application at {artifact}")
    print(f"recorded host-only build evidence at {manifest_path}")
    print("USB identity values were not recorded; nothing was flashed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
