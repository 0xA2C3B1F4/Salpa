#!/usr/bin/env python3
"""Build one clean-tree ESP32-S2 signed A/B application variant."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import git_output, is_within, sha256_file


BASE_FEATURES = [
    "ctaphid-bringup",
    "fido-stack",
    "mcu-esp32s2",
    "signed-ab-update",
    "usb-signed-update",
]
VARIANTS = {
    "base": {"feature": None, "version": "0.1.0"},
    "failure": {"feature": "signed-ab-failure-test", "version": "0.1.1-ab-fail"},
    "success": {"feature": "signed-ab-success-test", "version": "0.1.2-ab-pass"},
}
TARGET = "xtensa-esp32s2-none-elf"


class BuildError(RuntimeError):
    """The signed A/B application build gate was not met."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def command_output(path: Path, *args: str) -> str:
    return subprocess.run(
        list(args), cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=sorted(VARIANTS), required=True)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--update-key-digest", required=True)
    parser.add_argument("--secure-version", required=True, type=int)
    parser.add_argument("--non-strapping-user-presence", action="store_true")
    args = parser.parse_args()
    root = repository_root()
    build_dir = args.build_dir.expanduser().resolve()
    variant = VARIANTS[args.variant]
    features = BASE_FEATURES.copy()
    if variant["feature"]:
        features.append(str(variant["feature"]))
    security_profile = "wemos-s2-mini-signed-ab-test"
    if args.non_strapping_user_presence:
        features.append("non-strapping-user-presence")
        security_profile = "wemos-s2-mini-non-strapping-up-test"
    required_environment = [
        "RISSO_KEY_USB_PID",
        "RISSO_KEY_USB_SERIAL",
        "RISSO_KEY_USB_VID",
    ]
    update_key_digest = args.update_key_digest
    secure_version = args.secure_version

    try:
        if is_within(build_dir, root):
            raise BuildError("build directory must stay outside the source repository")
        if build_dir.exists() and any(build_dir.iterdir()):
            raise BuildError("build directory must be new or empty")
        missing = [name for name in required_environment if not os.environ.get(name)]
        if missing:
            raise BuildError(f"missing required environment: {', '.join(missing)}")
        if re.fullmatch(r"[0-9a-f]{64}", update_key_digest) is None:
            raise BuildError("--update-key-digest must be 64 lowercase hexadecimal characters")
        if not 0 <= secure_version <= 0xFFFF_FFFF:
            raise BuildError("--secure-version must fit in an unsigned 32-bit integer")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("source tree must be clean before recording build evidence")

        build_dir.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "CARGO_TARGET_DIR": str(build_dir),
                "RISSO_KEY_MCU": "esp32s2",
                "RISSO_KEY_PARTITION_PROFILE": "signed-ab",
                "RISSO_KEY_UPDATE_KEY_DIGEST_HEX": update_key_digest,
                "ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION": str(secure_version),
            }
        )
        command = [
            str(root / "tools/cargo-esp"),
            "build",
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            ",".join(features),
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
                "command": ["./tools/cargo-esp", *command[1:]],
                "environment_values_recorded": False,
                "features": features,
                "mcu": "esp32s2",
                "partition_profile": "signed-ab",
                "required_environment": required_environment,
                "security_profile": security_profile,
            },
            "build_only": True,
            "efuse_operations_performed": False,
            "flash_authorized": False,
            "generated_at": datetime.now(UTC).isoformat(),
            "image_version": variant["version"],
            "kind": "rissokey-signed-ab-application",
            "schema": 1,
            "secure_version": secure_version,
            "trusted_public_key_digest": update_key_digest,
            "source": {
                "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
                "commit": git_output(root, "rev-parse", "HEAD"),
                "partition_table_sha256": sha256_file(root / "partitions-ab.csv"),
                "security_profiles_sha256": sha256_file(root / "policy/security-profiles.json"),
                "tree": git_output(root, "rev-parse", "HEAD^{tree}"),
            },
            "toolchain": {
                "cargo": command_output(root, "cargo", "-vV"),
                "rustc": command_output(root, "rustc", "-vV"),
            },
            "variant": args.variant,
        }
        manifest_path = build_dir / f"rissokey-signed-ab-{args.variant}-build.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"signed A/B application build failed: {error}", file=sys.stderr)
        return 1

    print(f"built signed A/B {args.variant} application at {artifact}")
    print(f"recorded host-only build evidence at {manifest_path}")
    print("USB identity values were not recorded; nothing was flashed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
