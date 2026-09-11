#!/usr/bin/env python3
"""Build the reversible ESP32-S2 0xE000 migration bootloader off-device."""

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
from host_common import git_output, is_within, parse_sdkconfig, sha256_file


PINNED_IDF_COMMIT = "fff9895c82d744c7237be8847347bdd1b07c6643"
PROJECT_PATH = Path("security/esp-idf-bootloader")
DEFAULTS_PATH = PROJECT_PATH / "sdkconfig.defaults.esp32s2-e000-development"
TABLE_OFFSET = 0xE000
BOOTLOADER_OFFSET = 0x1000


class BuildError(RuntimeError):
    """The reversible migration bootloader build gate was not met."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def validate_sdkconfig(path: Path) -> None:
    values = parse_sdkconfig(path)
    required = {
        "CONFIG_IDF_TARGET": '"esp32s2"',
        "CONFIG_PARTITION_TABLE_OFFSET": "0xE000",
        "CONFIG_ESPTOOLPY_FLASHMODE_DIO": "y",
        "CONFIG_ESPTOOLPY_FLASHFREQ_40M": "y",
        "CONFIG_ESPTOOLPY_FLASHSIZE_4MB": "y",
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise BuildError(f"generated sdkconfig does not set {key}={expected}")

    forbidden = {
        "CONFIG_SECURE_BOOT",
        "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES",
        "CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT",
        "CONFIG_SECURE_BOOT_INSECURE",
        "CONFIG_SECURE_DISABLE_ROM_DL_MODE",
        "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE",
        "CONFIG_SECURE_FLASH_ENC_ENABLED",
        "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE",
        "CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT",
    }
    enabled = sorted(key for key in forbidden if values.get(key) == "y")
    if enabled:
        raise BuildError(f"generated sdkconfig enables forbidden options: {', '.join(enabled)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a non-secure ESP32-S2 bootloader that reads the partition table "
            "at 0xE000. This command does not access hardware."
        )
    )
    parser.add_argument(
        "--idf-path",
        type=Path,
        default=os.environ.get("IDF_PATH"),
        required="IDF_PATH" not in os.environ,
    )
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()

    root = repository_root()
    idf_path = args.idf_path.expanduser().resolve()
    build_dir = args.build_dir.expanduser().resolve()
    project_dir = root / PROJECT_PATH
    defaults = root / DEFAULTS_PATH

    try:
        if is_within(build_dir, root):
            raise BuildError("build directory must stay outside the source repository")
        if build_dir.exists() and any(build_dir.iterdir()):
            raise BuildError("build directory must be new or empty")
        if not (idf_path / "tools/idf.py").is_file():
            raise BuildError("--idf-path is not an ESP-IDF checkout")
        idf_commit = git_output(idf_path, "rev-parse", "HEAD")
        if idf_commit != PINNED_IDF_COMMIT:
            raise BuildError(
                f"ESP-IDF must be pinned to {PINNED_IDF_COMMIT}; found {idf_commit}"
            )
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("source tree must be clean before recording build evidence")

        build_dir.mkdir(parents=True, exist_ok=True)
        sdkconfig = build_dir / "sdkconfig"
        command = [
            sys.executable,
            str(idf_path / "tools/idf.py"),
            "-B",
            str(build_dir),
            "-D",
            "IDF_TARGET=esp32s2",
            "-D",
            f"SDKCONFIG={sdkconfig}",
            "-D",
            f"SDKCONFIG_DEFAULTS={defaults}",
            "bootloader",
        ]
        environment = os.environ.copy()
        environment["IDF_PATH"] = str(idf_path)
        environment["IDF_PYTHON_ENV_PATH"] = sys.prefix
        environment["ESP_IDF_VERSION"] = "6.1"
        subprocess.run(command, cwd=project_dir, env=environment, check=True)

        validate_sdkconfig(sdkconfig)
        bootloader_bin = build_dir / "bootloader/bootloader.bin"
        bootloader_elf = build_dir / "bootloader/bootloader.elf"
        for artifact in (bootloader_bin, bootloader_elf):
            if not artifact.is_file() or artifact.is_symlink():
                raise BuildError(f"missing regular build artifact: {artifact.name}")
        available = TABLE_OFFSET - BOOTLOADER_OFFSET
        if bootloader_bin.stat().st_size > available:
            raise BuildError("bootloader does not fit before the 0xE000 partition table")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("bootloader build modified the source tree")

        manifest = {
            "artifacts": {
                "bootloader_bin": {
                    "file": "bootloader/bootloader.bin",
                    "sha256": sha256_file(bootloader_bin),
                    "size": bootloader_bin.stat().st_size,
                },
                "bootloader_elf": {
                    "file": "bootloader/bootloader.elf",
                    "sha256": sha256_file(bootloader_elf),
                    "size": bootloader_elf.stat().st_size,
                },
            },
            "build_only": True,
            "efuse_operations_performed": False,
            "esp_idf_commit": idf_commit,
            "flash_authorized": False,
            "generated_at": datetime.now(UTC).isoformat(),
            "kind": "rissokey-e000-migration-bootloader",
            "layout": {
                "bootloader_offset": BOOTLOADER_OFFSET,
                "partition_table_offset": TABLE_OFFSET,
                "partition_table_sha256": sha256_file(root / "partitions-e000.csv"),
            },
            "sdkconfig_sha256": sha256_file(sdkconfig),
            "schema": 1,
            "source_commit": git_output(root, "rev-parse", "HEAD"),
            "source_tree": git_output(root, "rev-parse", "HEAD^{tree}"),
            "warning": "Reversible layout migration only; Secure Boot and flash encryption are disabled.",
        }
        manifest_path = build_dir / "rissokey-e000-bootloader-build.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"0xE000 migration bootloader build failed: {error}", file=sys.stderr)
        return 1

    print(f"built reversible 0xE000 migration bootloader at {bootloader_bin}")
    print(f"recorded host-only build evidence at {manifest_path}")
    print("nothing was flashed and no eFuse operation was performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
