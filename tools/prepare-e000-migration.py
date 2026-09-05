#!/usr/bin/env python3
"""Prepare a hash-bound ESP32-S2 0xE000 migration package off-device."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import git_output, is_within, sha256_file


ESPFLASH_VERSION = "espflash 4.5.0"
BOOTLOADER_OFFSET = 0x1000
TABLE_OFFSET = 0xE000
APP_OFFSET = 0x10000
APP_SIZE = 0x3C0000
LEGACY_TABLE_OFFSET = 0x8000
LEGACY_NVS_PHY_OFFSET = 0x9000
LEGACY_NVS_PHY_SIZE = 0x7000
LEGACY_APP_SIZE = 0x3D0000
LEGACY_BOOTLOADER_REGION_SIZE = LEGACY_TABLE_OFFSET - BOOTLOADER_OFFSET
LEGACY_TABLE_SECTOR_SIZE = 0x1000
MOVED_DATA_OFFSET = 0x3D0000
MOVED_DATA_SIZE = 0x7000
FIDO_STORE_OFFSET = 0x3E0000
FIDO_STORE_SIZE = 0x20000
SECURITY_PROFILE = "wemos-s2-mini-e000-migration-test"


class PackageError(RuntimeError):
    """Migration-package provenance or layout validation failed."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def command_output(*args: str) -> str:
    return subprocess.run(
        list(args), check=True, capture_output=True, text=True
    ).stdout.strip()


def load_manifest(path: Path, expected_kind: str) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"manifest must be a regular file: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackageError(f"cannot read manifest {path}: {error}") from error
    if (
        not isinstance(document, dict)
        or document.get("schema") != 1
        or document.get("kind") != expected_kind
    ):
        raise PackageError(f"unexpected manifest kind or schema: {path}")
    return document


def manifest_artifact(
    manifest_path: Path,
    record: object,
) -> Path:
    if not isinstance(record, dict):
        raise PackageError(f"invalid artifact record in {manifest_path}")
    relative = record.get("file")
    expected_hash = record.get("sha256")
    expected_size = record.get("size")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or not isinstance(expected_hash, str)
        or not isinstance(expected_size, int)
    ):
        raise PackageError(f"invalid artifact fields in {manifest_path}")
    base = manifest_path.parent.resolve()
    artifact = (base / relative).resolve()
    if not is_within(artifact, base):
        raise PackageError(f"artifact escapes manifest directory: {relative}")
    if not artifact.is_file() or artifact.is_symlink():
        raise PackageError(f"artifact must be a regular file: {artifact}")
    if (
        artifact.stat().st_size != expected_size
        or sha256_file(artifact) != expected_hash
    ):
        raise PackageError(f"artifact does not match manifest: {artifact.name}")
    return artifact


def copy_region(source: Path, destination: Path, offset: int, size: int) -> None:
    with source.open("rb") as source_handle:
        source_handle.seek(offset)
        data = source_handle.read(size)
    if len(data) != size:
        raise PackageError(
            f"short legacy recovery image at 0x{offset:x}: {len(data)} of {size} bytes"
        )
    destination.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Combine clean-tree application and bootloader evidence into a reversible "
            "0xE000 migration package. This command does not access hardware."
        )
    )
    parser.add_argument("--espflash", required=True, type=Path)
    parser.add_argument("--bootloader-manifest", required=True, type=Path)
    parser.add_argument("--application-manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    root = repository_root()
    espflash = args.espflash.expanduser().resolve()
    boot_manifest_path = args.bootloader_manifest.expanduser().resolve()
    app_manifest_path = args.application_manifest.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()

    try:
        if is_within(output_dir, root):
            raise PackageError(
                "output directory must stay outside the source repository"
            )
        if output_dir.exists() and any(output_dir.iterdir()):
            raise PackageError("output directory must be new or empty")
        if not espflash.is_file() or espflash.is_symlink():
            raise PackageError("--espflash must be a regular file")
        if (
            command_output(str(espflash), "--version").splitlines()[0]
            != ESPFLASH_VERSION
        ):
            raise PackageError(f"espflash must be exactly {ESPFLASH_VERSION}")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise PackageError("source tree must be clean before packaging")
        subprocess.run(
            [sys.executable, str(root / "scripts/check_partition_layouts.py")],
            cwd=root,
            check=True,
        )

        boot_manifest = load_manifest(
            boot_manifest_path, "rissokey-e000-migration-bootloader"
        )
        app_manifest = load_manifest(
            app_manifest_path, "rissokey-e000-migration-application"
        )
        source_commit = git_output(root, "rev-parse", "HEAD")
        source_tree = git_output(root, "rev-parse", "HEAD^{tree}")
        if (
            boot_manifest.get("source_commit") != source_commit
            or boot_manifest.get("source_tree") != source_tree
        ):
            raise PackageError("bootloader evidence belongs to another source revision")
        app_source = app_manifest.get("source")
        if not isinstance(app_source, dict) or (
            app_source.get("commit") != source_commit
            or app_source.get("tree") != source_tree
        ):
            raise PackageError(
                "application evidence belongs to another source revision"
            )

        partition_csv_hash = sha256_file(root / "partitions-e000.csv")
        boot_layout = boot_manifest.get("layout")
        app_build = app_manifest.get("build")
        if not isinstance(boot_layout, dict) or (
            boot_layout.get("bootloader_offset") != BOOTLOADER_OFFSET
            or boot_layout.get("partition_table_offset") != TABLE_OFFSET
            or boot_layout.get("partition_table_sha256") != partition_csv_hash
        ):
            raise PackageError(
                "bootloader evidence is not bound to the current 0xE000 layout"
            )
        if not isinstance(app_build, dict) or (
            app_build.get("partition_profile") != "e000-migration"
            or app_build.get("security_profile") != SECURITY_PROFILE
        ):
            raise PackageError("application evidence uses the wrong migration profile")
        if app_source.get("partition_table_sha256") != partition_csv_hash:
            raise PackageError(
                "application evidence has the wrong partition-table hash"
            )
        if app_source.get("security_profiles_sha256") != sha256_file(
            root / "policy/security-profiles.json"
        ):
            raise PackageError(
                "application evidence has the wrong security-policy hash"
            )

        boot_artifacts = boot_manifest.get("artifacts")
        if not isinstance(boot_artifacts, dict):
            raise PackageError("bootloader manifest has no artifact map")
        bootloader = manifest_artifact(
            boot_manifest_path, boot_artifacts.get("bootloader_bin")
        )
        application_elf = manifest_artifact(
            app_manifest_path, app_manifest.get("artifact")
        )
        if bootloader.stat().st_size > TABLE_OFFSET - BOOTLOADER_OFFSET:
            raise PackageError("bootloader overlaps the partition table")

        output_dir.mkdir(parents=True, exist_ok=True)
        package_bootloader = output_dir / "bootloader.bin"
        package_table = output_dir / "partition-table.bin"
        package_application = output_dir / "application.bin"
        legacy_merged = output_dir / ".legacy-merged.bin"
        legacy_bootloader = output_dir / "legacy-bootloader-region.bin"
        legacy_table = output_dir / "legacy-partition-table-sector.bin"
        legacy_application = output_dir / "legacy-application.bin"
        legacy_table_payload = output_dir / ".legacy-partition-table.bin"
        shutil.copy2(bootloader, package_bootloader)
        subprocess.run(
            [
                str(espflash),
                "partition-table",
                "--to-binary",
                "--output",
                str(package_table),
                str(root / "partitions-e000.csv"),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(espflash),
                "save-image",
                "--chip",
                "esp32s2",
                "--flash-freq",
                "40mhz",
                "--flash-mode",
                "dio",
                "--flash-size",
                "4mb",
                "--bootloader",
                str(package_bootloader),
                "--partition-table",
                str(root / "partitions-e000.csv"),
                "--partition-table-offset",
                "0xe000",
                "--target-app-partition",
                "factory",
                str(application_elf),
                str(package_application),
            ],
            check=True,
        )
        if package_table.stat().st_size != 0xC00:
            raise PackageError("generated partition table must be exactly 0xC00 bytes")
        if package_application.stat().st_size > APP_SIZE:
            raise PackageError(
                "application image does not fit the migration factory partition"
            )

        subprocess.run(
            [
                str(espflash),
                "partition-table",
                "--to-binary",
                "--output",
                str(legacy_table_payload),
                str(root / "partitions.csv"),
            ],
            check=True,
        )
        if legacy_table_payload.stat().st_size != 0xC00:
            raise PackageError(
                "generated legacy partition table must be exactly 0xC00 bytes"
            )
        subprocess.run(
            [
                str(espflash),
                "save-image",
                "--chip",
                "esp32s2",
                "--flash-freq",
                "40mhz",
                "--flash-mode",
                "dio",
                "--flash-size",
                "4mb",
                "--merge",
                "--skip-padding",
                "--partition-table",
                str(root / "partitions.csv"),
                "--partition-table-offset",
                hex(LEGACY_TABLE_OFFSET),
                "--target-app-partition",
                "factory",
                str(application_elf),
                str(legacy_merged),
            ],
            check=True,
        )
        merged_size = legacy_merged.stat().st_size
        if not APP_OFFSET < merged_size <= APP_OFFSET + LEGACY_APP_SIZE:
            raise PackageError("legacy merged image does not fit the factory partition")
        merged = legacy_merged.read_bytes()
        if (
            merged[:BOOTLOADER_OFFSET] != b"\xff" * BOOTLOADER_OFFSET
            or merged[BOOTLOADER_OFFSET] != 0xE9
            or merged[LEGACY_TABLE_OFFSET : LEGACY_TABLE_OFFSET + 2] != b"\xaa\x50"
            or merged[LEGACY_NVS_PHY_OFFSET:APP_OFFSET]
            != b"\xff" * LEGACY_NVS_PHY_SIZE
            or merged[APP_OFFSET] != 0xE9
        ):
            raise PackageError(
                "legacy merged image has unexpected offsets or magic bytes"
            )
        copy_region(
            legacy_merged,
            legacy_bootloader,
            BOOTLOADER_OFFSET,
            LEGACY_BOOTLOADER_REGION_SIZE,
        )
        copy_region(
            legacy_merged,
            legacy_table,
            LEGACY_TABLE_OFFSET,
            LEGACY_TABLE_SECTOR_SIZE,
        )
        copy_region(
            legacy_merged,
            legacy_application,
            APP_OFFSET,
            merged_size - APP_OFFSET,
        )
        legacy_merged.unlink()
        legacy_table_bytes = legacy_table.read_bytes()
        if (
            legacy_table_bytes[:0xC00] != legacy_table_payload.read_bytes()
            or legacy_table_bytes[0xC00:] != b"\xff" * 0x400
        ):
            raise PackageError("legacy recovery table does not match partitions.csv")
        legacy_table_payload.unlink()
        if legacy_application.read_bytes() != package_application.read_bytes():
            raise PackageError("legacy and migration application images differ")

        shutil.copy2(boot_manifest_path, output_dir / "bootloader-build.json")
        shutil.copy2(app_manifest_path, output_dir / "application-build.json")
        files = {
            name: {
                "file": name,
                "sha256": sha256_file(output_dir / name),
                "size": (output_dir / name).stat().st_size,
            }
            for name in (
                "application-build.json",
                "application.bin",
                "bootloader-build.json",
                "bootloader.bin",
                "legacy-application.bin",
                "legacy-bootloader-region.bin",
                "legacy-partition-table-sector.bin",
                "partition-table.bin",
            )
        }
        manifest = {
            "addresses": {
                "application": APP_OFFSET,
                "bootloader": BOOTLOADER_OFFSET,
                "moved_nvs_and_phy": MOVED_DATA_OFFSET,
                "partition_table": TABLE_OFFSET,
            },
            "created_at": datetime.now(UTC).isoformat(),
            "device_preconditions": {
                "chip": "esp32s2",
                "flash_encryption": "disabled",
                "flash_size": 0x400000,
                "rom_download": "enabled",
                "secure_boot": "disabled",
            },
            "files": files,
            "kind": "rissokey-e000-migration-package",
            "legacy_recovery_addresses": {
                "application": APP_OFFSET,
                "bootloader": BOOTLOADER_OFFSET,
                "legacy_nvs_and_phy": LEGACY_NVS_PHY_OFFSET,
                "moved_nvs_and_phy": MOVED_DATA_OFFSET,
                "partition_table": LEGACY_TABLE_OFFSET,
            },
            "layout": {
                "application_size": APP_SIZE,
                "fido_store_offset": FIDO_STORE_OFFSET,
                "fido_store_size": FIDO_STORE_SIZE,
                "moved_nvs_and_phy_size": MOVED_DATA_SIZE,
                "partition_csv_sha256": partition_csv_hash,
            },
            "recovery": {
                "full_flash_backup_supported": True,
                "full_flash_size": 0x400000,
                "functional_legacy_restore_preserves_fido_store": True,
                "functional_legacy_restore_resets_nvs_and_phy": True,
                "functional_legacy_restore_supported": True,
                "restore_before_efuse_changes": True,
            },
            "schema": 2,
            "security_profile": SECURITY_PROFILE,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "write_order": [
                "application",
                "erase_moved_nvs_and_phy",
                "partition_table",
                "bootloader",
            ],
            "writes_fido_store": False,
        }
        manifest_path = output_dir / "rissokey-e000-migration.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (PackageError, OSError, subprocess.CalledProcessError) as error:
        print(f"0xE000 migration package failed: {error}", file=sys.stderr)
        return 1

    print(f"prepared reversible 0xE000 migration package at {output_dir}")
    print(
        "included full-backup and disposable functional-rollback paths; "
        "nothing was flashed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
