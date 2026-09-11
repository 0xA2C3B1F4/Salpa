#!/usr/bin/env python3
"""Back up, apply, or restore the reversible ESP32-S2 0xE000 migration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import is_within, sha256_file


FLASH_SIZE = 0x400000
BOOTLOADER_OFFSET = 0x1000
LEGACY_TABLE_OFFSET = 0x8000
LEGACY_NVS_PHY_OFFSET = 0x9000
LEGACY_NVS_PHY_SIZE = 0x7000
APP_OFFSET = 0x10000
FIDO_STORE_OFFSET = 0x3E0000
FIDO_STORE_SIZE = 0x20000
MOVED_DATA_OFFSET = 0x3D0000
MOVED_DATA_SIZE = 0x7000
PACKAGE_MANIFEST = "rissokey-e000-migration.json"
BACKUP_MANIFEST = "rissokey-e000-backup.json"
ESPTOOL_VERSION = "5.4.0"
SECURITY_FIELDS = [
    "DIS_DOWNLOAD_MODE",
    "DIS_USB_DOWNLOAD_MODE",
    "ENABLE_SECURITY_DOWNLOAD",
    "SECURE_BOOT_EN",
    "SPI_BOOT_CRYPT_CNT",
]


class DeviceError(RuntimeError):
    """A reversible migration device gate failed."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def sha256_region(path: Path, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        handle.seek(offset)
        remaining = size
        while remaining:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                raise DeviceError(
                    f"short flash backup while hashing region at 0x{offset:x}"
                )
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise DeviceError(f"{label} must be a regular file: {path}")


def load_json(path: Path, label: str) -> dict[str, object]:
    regular_file(path, label)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DeviceError(f"cannot read {label}: {error}") from error
    if not isinstance(document, dict):
        raise DeviceError(f"{label} must contain a JSON object")
    return document


def verify_package(package_dir: Path) -> tuple[dict[str, object], dict[str, Path]]:
    manifest_path = package_dir / PACKAGE_MANIFEST
    manifest = load_json(manifest_path, "migration package manifest")
    schema = manifest.get("schema")
    if (
        schema not in (1, 2)
        or manifest.get("kind") != "rissokey-e000-migration-package"
    ):
        raise DeviceError("unsupported migration package")
    expected_top_level = {
        "writes_fido_store": False,
        "security_profile": "wemos-s2-mini-e000-migration-test",
    }
    for key, expected in expected_top_level.items():
        if manifest.get(key) != expected:
            raise DeviceError(f"migration package has unsafe {key}")
    addresses = manifest.get("addresses")
    layout = manifest.get("layout")
    recovery = manifest.get("recovery")
    if not isinstance(addresses, dict) or addresses != {
        "application": 0x10000,
        "bootloader": 0x1000,
        "moved_nvs_and_phy": MOVED_DATA_OFFSET,
        "partition_table": 0xE000,
    }:
        raise DeviceError("migration package has unexpected write addresses")
    if not isinstance(layout, dict) or (
        layout.get("fido_store_offset") != FIDO_STORE_OFFSET
        or layout.get("fido_store_size") != FIDO_STORE_SIZE
        or layout.get("moved_nvs_and_phy_size") != MOVED_DATA_SIZE
    ):
        raise DeviceError(
            "migration package does not preserve the credential-store layout"
        )
    if not isinstance(recovery, dict) or (
        recovery.get("full_flash_size") != FLASH_SIZE
        or recovery.get("restore_before_efuse_changes") is not True
    ):
        raise DeviceError("migration package does not provide reversible recovery")
    if schema == 1:
        if recovery.get("full_flash_backup_required") is not True:
            raise DeviceError(
                "legacy migration package does not require its full backup"
            )
    elif (
        recovery.get("full_flash_backup_supported") is not True
        or recovery.get("functional_legacy_restore_supported") is not True
        or recovery.get("functional_legacy_restore_preserves_fido_store") is not True
        or recovery.get("functional_legacy_restore_resets_nvs_and_phy") is not True
    ):
        raise DeviceError(
            "migration package has an incomplete functional restore contract"
        )

    records = manifest.get("files")
    if not isinstance(records, dict):
        raise DeviceError("migration package has no file records")
    required = {"application.bin", "bootloader.bin", "partition-table.bin"}
    if schema == 2:
        required.update(
            {
                "legacy-application.bin",
                "legacy-bootloader-region.bin",
                "legacy-partition-table-sector.bin",
            }
        )
        if manifest.get("legacy_recovery_addresses") != {
            "application": APP_OFFSET,
            "bootloader": BOOTLOADER_OFFSET,
            "legacy_nvs_and_phy": LEGACY_NVS_PHY_OFFSET,
            "moved_nvs_and_phy": MOVED_DATA_OFFSET,
            "partition_table": LEGACY_TABLE_OFFSET,
        }:
            raise DeviceError(
                "migration package has unexpected legacy restore addresses"
            )
    if not required.issubset(records):
        raise DeviceError("migration package is missing flash artifacts")
    files: dict[str, Path] = {}
    for name, record in records.items():
        if not isinstance(name, str) or not isinstance(record, dict):
            raise DeviceError("invalid migration package file record")
        if record.get("file") != name:
            raise DeviceError("migration package file record is not canonical")
        path = (package_dir / name).resolve()
        if not is_within(path, package_dir) or path.parent != package_dir:
            raise DeviceError("migration package file escapes its directory")
        regular_file(path, "migration package file")
        if (
            record.get("size") != path.stat().st_size
            or record.get("sha256") != sha256_file(path)
        ):
            raise DeviceError(f"migration package file hash mismatch: {name}")
        files[name] = path
    if files["partition-table.bin"].stat().st_size != 0xC00:
        raise DeviceError("partition table has an unexpected size")
    if files["bootloader.bin"].stat().st_size > 0xD000:
        raise DeviceError("bootloader overlaps the 0xE000 partition table")
    if files["application.bin"].stat().st_size > 0x3C0000:
        raise DeviceError("application exceeds the factory partition")
    if schema == 2:
        if files["legacy-bootloader-region.bin"].stat().st_size != 0x7000:
            raise DeviceError("legacy bootloader region has an unexpected size")
        if files["legacy-partition-table-sector.bin"].stat().st_size != 0x1000:
            raise DeviceError("legacy partition-table sector has an unexpected size")
        if files["legacy-application.bin"].stat().st_size > 0x3D0000:
            raise DeviceError("legacy application exceeds the factory partition")
        if files["legacy-application.bin"].read_bytes() != files[
            "application.bin"
        ].read_bytes():
            raise DeviceError("legacy and migration application images differ")
        if files["legacy-bootloader-region.bin"].read_bytes()[:1] != b"\xe9":
            raise DeviceError("legacy bootloader image has invalid magic")
        if files["legacy-partition-table-sector.bin"].read_bytes()[:2] != b"\xaa\x50":
            raise DeviceError("legacy partition table has invalid magic")
    return manifest, files


def tool_version(python: Path) -> None:
    if not python.is_file() or not python.resolve().is_file():
        raise DeviceError(f"Espressif Python interpreter is not a file: {python}")
    result = subprocess.run(
        [
            str(python),
            "-c",
            "import esptool; print(esptool.__version__)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip() != ESPTOOL_VERSION:
        raise DeviceError(f"esptool must be exactly {ESPTOOL_VERSION}")


def esptool_command(python: Path, port: str, *arguments: str) -> list[str]:
    return [
        str(python),
        "-m",
        "esptool",
        "--chip",
        "esp32s2",
        "--port",
        port,
        "--before",
        "no-reset",
        "--after",
        "no-reset",
        *arguments,
    ]


def run_esptool(
    python: Path,
    port: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        esptool_command(python, port, *arguments),
        check=True,
        capture_output=True,
        text=True,
    )


def check_flash_size(python: Path, port: str) -> None:
    result = run_esptool(python, port, "flash-id")
    if re.search(r"Detected flash size:\s*4MB\b", result.stdout) is None:
        raise DeviceError("device must report exactly 4 MB of flash")


def capture_security_summary(
    python: Path,
    port: str,
    output: Path,
) -> dict[str, object]:
    command = [
        str(python),
        "-m",
        "espefuse",
        "--chip",
        "esp32s2",
        "--port",
        port,
        "--before",
        "no-reset",
        "--after",
        "no-reset",
        "summary",
        *SECURITY_FIELDS,
        "--format",
        "json",
        "--file",
        str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)
    os.chmod(output, 0o600)
    summary = load_json(output, "security preflight")
    if set(summary) != set(SECURITY_FIELDS):
        raise DeviceError("security preflight omitted required eFuse fields")
    for name in SECURITY_FIELDS:
        record = summary.get(name)
        if not isinstance(record, dict) or not record.get("readable"):
            raise DeviceError(f"security preflight cannot read {name}")
    if summary["SECURE_BOOT_EN"].get("value") is not False:
        raise DeviceError(
            "Secure Boot is already enabled; reversible migration is blocked"
        )
    crypt = summary["SPI_BOOT_CRYPT_CNT"]
    if crypt.get("raw_value") != "0x0" or crypt.get("value") != "Disable":
        raise DeviceError(
            "flash encryption state is not the required disabled baseline"
        )
    for name in (
        "DIS_DOWNLOAD_MODE",
        "DIS_USB_DOWNLOAD_MODE",
        "ENABLE_SECURITY_DOWNLOAD",
    ):
        if summary[name].get("value") is not False:
            raise DeviceError("ROM download recovery is not fully available")
    return summary


def temporary_root() -> Path:
    raw = os.environ.get("TMPDIR")
    if not raw:
        raise DeviceError("TMPDIR is required for ephemeral device readback")
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise DeviceError("TMPDIR is not an available directory")
    return path


def read_flash_digest(
    python: Path,
    port: str,
    offset: int,
    size: int,
) -> str:
    with tempfile.TemporaryDirectory(
        prefix="salpa-e000-readback-", dir=temporary_root()
    ) as directory:
        path = Path(directory) / "region.bin"
        run_esptool(
            python,
            port,
            "read-flash",
            "--no-progress",
            hex(offset),
            hex(size),
            str(path),
        )
        os.chmod(path, 0o600)
        if path.stat().st_size != size:
            raise DeviceError(f"short device readback at 0x{offset:x}")
        return sha256_file(path)


def write_and_verify(
    python: Path,
    port: str,
    offset: int,
    artifact: Path,
) -> None:
    run_esptool(
        python,
        port,
        "write-flash",
        "--flash-mode",
        "dio",
        "--flash-freq",
        "40m",
        "--flash-size",
        "4MB",
        hex(offset),
        str(artifact),
    )
    run_esptool(python, port, "verify-flash", hex(offset), str(artifact))


def erase_and_verify(
    python: Path,
    port: str,
    offset: int,
    size: int,
) -> None:
    run_esptool(python, port, "erase-region", hex(offset), hex(size))
    expected = hashlib.sha256(b"\xff" * size).hexdigest()
    if read_flash_digest(python, port, offset, size) != expected:
        raise DeviceError(f"flash region at 0x{offset:x} did not erase cleanly")


def compare_store_after(
    python: Path,
    port: str,
    expected_digest: str,
    operation: str,
) -> None:
    if read_flash_digest(
        python, port, FIDO_STORE_OFFSET, FIDO_STORE_SIZE
    ) != expected_digest:
        raise DeviceError(f"credential storage changed during {operation}")


def ensure_new_evidence_directory(path: Path, root: Path) -> None:
    if is_within(path, root):
        raise DeviceError("device evidence must stay outside the repository")
    if path.exists() and any(path.iterdir()):
        raise DeviceError("evidence directory must be new or empty")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def write_evidence(path: Path, document: dict[str, object]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(path, 0o600)


def run_store_preserving_operation(
    python: Path,
    port: str,
    label: str,
    action: Callable[[], None],
) -> None:
    expected = read_flash_digest(python, port, FIDO_STORE_OFFSET, FIDO_STORE_SIZE)
    try:
        action()
    except (DeviceError, OSError, subprocess.CalledProcessError) as error:
        try:
            compare_store_after(python, port, expected, label)
        except (DeviceError, OSError, subprocess.CalledProcessError) as store_error:
            raise DeviceError(
                f"{label} failed and credential-storage preservation could not "
                "be confirmed"
            ) from store_error
        raise
    compare_store_after(python, port, expected, label)


def verify_backup(
    backup_dir: Path, package_dir: Path
) -> tuple[dict[str, object], Path]:
    manifest = load_json(backup_dir / BACKUP_MANIFEST, "migration backup manifest")
    if (
        manifest.get("schema") != 1
        or manifest.get("kind") != "rissokey-e000-full-flash-backup"
    ):
        raise DeviceError("unsupported migration backup")
    if manifest.get("package_manifest_sha256") != sha256_file(
        package_dir / PACKAGE_MANIFEST
    ):
        raise DeviceError("backup belongs to another migration package")
    full_flash = backup_dir / "full-flash.bin"
    regular_file(full_flash, "full flash backup")
    record = manifest.get("full_flash")
    if not isinstance(record, dict) or (
        record.get("file") != "full-flash.bin"
        or record.get("size") != FLASH_SIZE
        or record.get("sha256") != sha256_file(full_flash)
    ):
        raise DeviceError("full flash backup does not match its manifest")
    regions = manifest.get("regions")
    if not isinstance(regions, dict):
        raise DeviceError("backup has no protected-region evidence")
    fido = regions.get("fido_store")
    if not isinstance(fido, dict) or (
        fido.get("offset") != FIDO_STORE_OFFSET
        or fido.get("size") != FIDO_STORE_SIZE
        or fido.get("sha256")
        != sha256_region(full_flash, FIDO_STORE_OFFSET, FIDO_STORE_SIZE)
    ):
        raise DeviceError("credential-store backup evidence is invalid")
    return manifest, full_flash


def ensure_new_private_directory(path: Path, root: Path) -> None:
    if is_within(path, root):
        raise DeviceError("sensitive device backups must stay outside the repository")
    if path.exists() and any(path.iterdir()):
        raise DeviceError("backup directory must be new or empty")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def backup_device(args: argparse.Namespace) -> None:
    root = repository_root()
    package_dir = args.package_dir.expanduser().resolve()
    backup_dir = args.backup_dir.expanduser().resolve()
    python = args.esptool_python.expanduser().absolute()
    if args.acknowledgement != "CAPTURE_SENSITIVE_FULL_FLASH_BACKUP":
        raise DeviceError("backup acknowledgement is missing or incorrect")
    verify_package(package_dir)
    tool_version(python)
    ensure_new_private_directory(backup_dir, root)
    check_flash_size(python, args.port)
    security_path = backup_dir / "security-preflight.json"
    capture_security_summary(python, args.port, security_path)

    full_flash = backup_dir / "full-flash.bin"
    run_esptool(
        python,
        args.port,
        "read-flash",
        "--no-progress",
        "0x0",
        hex(FLASH_SIZE),
        str(full_flash),
    )
    os.chmod(full_flash, 0o600)
    if full_flash.stat().st_size != FLASH_SIZE:
        raise DeviceError("full flash backup has the wrong size")

    manifest = {
        "captured_at": datetime.now(UTC).isoformat(),
        "contains_credential_secrets": True,
        "efuse_operations_performed": False,
        "full_flash": {
            "file": "full-flash.bin",
            "sha256": sha256_file(full_flash),
            "size": FLASH_SIZE,
        },
        "kind": "rissokey-e000-full-flash-backup",
        "package_manifest_sha256": sha256_file(package_dir / PACKAGE_MANIFEST),
        "regions": {
            "fido_store": {
                "offset": FIDO_STORE_OFFSET,
                "sha256": sha256_region(
                    full_flash, FIDO_STORE_OFFSET, FIDO_STORE_SIZE
                ),
                "size": FIDO_STORE_SIZE,
            },
            "legacy_boot_table_nvs_phy": {
                "offset": 0x1000,
                "sha256": sha256_region(full_flash, 0x1000, 0xF000),
                "size": 0xF000,
            },
            "legacy_factory_tail": {
                "offset": 0x3D0000,
                "sha256": sha256_region(full_flash, 0x3D0000, 0x10000),
                "size": 0x10000,
            },
        },
        "schema": 1,
        "security_preflight_file": security_path.name,
        "warning": (
            "Private recovery evidence: never commit, publish, or share this "
            "directory."
        ),
    }
    manifest_path = backup_dir / BACKUP_MANIFEST
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(manifest_path, 0o600)
    print(f"captured private full-flash recovery backup at {backup_dir}")
    print("no flash write, erase, reset, or eFuse operation was performed")


def apply_migration(args: argparse.Namespace) -> None:
    package_dir = args.package_dir.expanduser().resolve()
    backup_dir = args.backup_dir.expanduser().resolve()
    python = args.esptool_python.expanduser().absolute()
    if args.acknowledgement != "APPLY_REVERSIBLE_E000_MIGRATION":
        raise DeviceError("apply acknowledgement is missing or incorrect")
    _, files = verify_package(package_dir)
    backup_manifest, _ = verify_backup(backup_dir, package_dir)
    tool_version(python)
    check_flash_size(python, args.port)
    security_path = backup_dir / "security-preapply.json"
    if security_path.exists():
        raise DeviceError("security preapply evidence already exists")
    capture_security_summary(python, args.port, security_path)

    current_flash = backup_dir / "preapply-full-flash.bin"
    if current_flash.exists():
        raise DeviceError("stale preapply flash capture exists")
    run_esptool(
        python,
        args.port,
        "read-flash",
        "--no-progress",
        "0x0",
        hex(FLASH_SIZE),
        str(current_flash),
    )
    os.chmod(current_flash, 0o600)
    try:
        if sha256_file(current_flash) != backup_manifest["full_flash"]["sha256"]:
            raise DeviceError("device flash changed after backup; capture a new backup")
    finally:
        current_flash.unlink(missing_ok=True)

    common_write = [
        "write-flash",
        "--flash-mode",
        "dio",
        "--flash-freq",
        "40m",
        "--flash-size",
        "4MB",
    ]
    run_esptool(
        python,
        args.port,
        *common_write,
        "0x10000",
        str(files["application.bin"]),
    )
    run_esptool(
        python,
        args.port,
        "verify-flash",
        "0x10000",
        str(files["application.bin"]),
    )
    run_esptool(
        python,
        args.port,
        "erase-region",
        hex(MOVED_DATA_OFFSET),
        hex(MOVED_DATA_SIZE),
    )
    erased = backup_dir / "post-erase-moved-data.bin"
    run_esptool(
        python,
        args.port,
        "read-flash",
        "--no-progress",
        hex(MOVED_DATA_OFFSET),
        hex(MOVED_DATA_SIZE),
        str(erased),
    )
    os.chmod(erased, 0o600)
    try:
        if erased.read_bytes() != b"\xff" * MOVED_DATA_SIZE:
            raise DeviceError("moved NVS/PHY region did not erase cleanly")
    finally:
        erased.unlink(missing_ok=True)
    run_esptool(
        python,
        args.port,
        *common_write,
        "0xe000",
        str(files["partition-table.bin"]),
    )
    run_esptool(
        python,
        args.port,
        "verify-flash",
        "0xe000",
        str(files["partition-table.bin"]),
    )
    run_esptool(
        python,
        args.port,
        *common_write,
        "0x1000",
        str(files["bootloader.bin"]),
    )
    run_esptool(
        python,
        args.port,
        "verify-flash",
        "0x1000",
        str(files["bootloader.bin"]),
    )

    post_store = backup_dir / "post-migration-fido-store.bin"
    run_esptool(
        python,
        args.port,
        "read-flash",
        "--no-progress",
        hex(FIDO_STORE_OFFSET),
        hex(FIDO_STORE_SIZE),
        str(post_store),
    )
    os.chmod(post_store, 0o600)
    try:
        expected_store_hash = backup_manifest["regions"]["fido_store"]["sha256"]
        if sha256_file(post_store) != expected_store_hash:
            raise DeviceError(
                "credential-store readback changed; restore the full backup"
            )
    finally:
        post_store.unlink(missing_ok=True)

    evidence = {
        "applied_at": datetime.now(UTC).isoformat(),
        "credential_store_matched_backup": True,
        "efuse_operations_performed": False,
        "kind": "rissokey-e000-migration-device-evidence",
        "package_manifest_sha256": sha256_file(package_dir / PACKAGE_MANIFEST),
        "schema": 1,
        "security_preapply_file": security_path.name,
        "write_order_completed": [
            "application",
            "erase_moved_nvs_and_phy",
            "partition_table",
            "bootloader",
        ],
    }
    evidence_path = backup_dir / "migration-applied.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(evidence_path, 0o600)
    print("applied and verified the reversible 0xE000 migration")
    print("credential storage matched its private backup; no eFuse was changed")
    print("the device remains in ROM download mode for an explicit reset")


def apply_disposable_migration(args: argparse.Namespace) -> None:
    root = repository_root()
    package_dir = args.package_dir.expanduser().resolve()
    evidence_dir = args.evidence_dir.expanduser().resolve()
    python = args.esptool_python.expanduser().absolute()
    if args.acknowledgement != "APPLY_UNUSED_DISPOSABLE_E000_WITHOUT_BACKUP":
        raise DeviceError("disposable apply acknowledgement is missing or incorrect")
    manifest, files = verify_package(package_dir)
    if manifest.get("schema") != 2:
        raise DeviceError("disposable apply requires a schema-2 recovery package")
    tool_version(python)
    ensure_new_evidence_directory(evidence_dir, root)
    check_flash_size(python, args.port)
    security_path = evidence_dir / "security-preapply.json"
    capture_security_summary(python, args.port, security_path)

    def apply_images() -> None:
        write_and_verify(python, args.port, APP_OFFSET, files["application.bin"])
        erase_and_verify(python, args.port, MOVED_DATA_OFFSET, MOVED_DATA_SIZE)
        write_and_verify(python, args.port, 0xE000, files["partition-table.bin"])
        write_and_verify(python, args.port, BOOTLOADER_OFFSET, files["bootloader.bin"])

    run_store_preserving_operation(
        python, args.port, "disposable 0xE000 migration", apply_images
    )
    write_evidence(
        evidence_dir / "migration-applied.json",
        {
            "applied_at": datetime.now(UTC).isoformat(),
            "credential_store_preserved": True,
            "efuse_operations_performed": False,
            "full_flash_backup_captured": False,
            "kind": "rissokey-e000-disposable-migration-evidence",
            "package_manifest_sha256": sha256_file(package_dir / PACKAGE_MANIFEST),
            "schema": 1,
            "security_preapply_file": security_path.name,
            "source_commit": manifest.get("source_commit"),
            "write_order_completed": [
                "application",
                "erase_moved_nvs_and_phy",
                "partition_table",
                "bootloader",
            ],
        },
    )
    print("applied and verified the disposable 0xE000 migration without a backup")
    print("credential storage was unchanged; no eFuse was changed")
    print("the device remains in ROM download mode for an explicit reset")


def restore_disposable_legacy(args: argparse.Namespace) -> None:
    root = repository_root()
    package_dir = args.package_dir.expanduser().resolve()
    evidence_dir = args.evidence_dir.expanduser().resolve()
    python = args.esptool_python.expanduser().absolute()
    if args.acknowledgement != "RESTORE_UNUSED_DISPOSABLE_LEGACY_WITHOUT_BACKUP":
        raise DeviceError("disposable restore acknowledgement is missing or incorrect")
    manifest, files = verify_package(package_dir)
    if manifest.get("schema") != 2:
        raise DeviceError("disposable restore requires a schema-2 recovery package")
    tool_version(python)
    ensure_new_evidence_directory(evidence_dir, root)
    check_flash_size(python, args.port)
    security_path = evidence_dir / "security-prerestore.json"
    capture_security_summary(python, args.port, security_path)

    def restore_images() -> None:
        write_and_verify(
            python, args.port, APP_OFFSET, files["legacy-application.bin"]
        )
        erase_and_verify(python, args.port, MOVED_DATA_OFFSET, MOVED_DATA_SIZE)
        erase_and_verify(
            python, args.port, LEGACY_NVS_PHY_OFFSET, LEGACY_NVS_PHY_SIZE
        )
        write_and_verify(
            python,
            args.port,
            LEGACY_TABLE_OFFSET,
            files["legacy-partition-table-sector.bin"],
        )
        write_and_verify(
            python,
            args.port,
            BOOTLOADER_OFFSET,
            files["legacy-bootloader-region.bin"],
        )

    run_store_preserving_operation(
        python, args.port, "disposable legacy restore", restore_images
    )
    write_evidence(
        evidence_dir / "legacy-restored.json",
        {
            "credential_store_preserved": True,
            "efuse_operations_performed": False,
            "exact_pre_migration_nvs_restored": False,
            "full_flash_backup_used": False,
            "kind": "rissokey-e000-disposable-legacy-restore-evidence",
            "legacy_nvs_and_phy_erased": True,
            "package_manifest_sha256": sha256_file(package_dir / PACKAGE_MANIFEST),
            "restored_at": datetime.now(UTC).isoformat(),
            "schema": 1,
            "security_prerestore_file": security_path.name,
            "source_commit": manifest.get("source_commit"),
            "write_order_completed": [
                "legacy_application",
                "erase_moved_nvs_and_phy",
                "erase_legacy_nvs_and_phy",
                "legacy_partition_table",
                "legacy_bootloader",
            ],
        },
    )
    print("restored and verified the functional legacy layout without a backup")
    print("legacy NVS/PHY were erased and credential storage was unchanged")
    print("no eFuse was changed; the device remains in ROM download mode")


def restore_backup(args: argparse.Namespace) -> None:
    package_dir = args.package_dir.expanduser().resolve()
    backup_dir = args.backup_dir.expanduser().resolve()
    python = args.esptool_python.expanduser().absolute()
    if args.acknowledgement != "RESTORE_FULL_PRE_MIGRATION_FLASH":
        raise DeviceError("restore acknowledgement is missing or incorrect")
    verify_package(package_dir)
    _, full_flash = verify_backup(backup_dir, package_dir)
    tool_version(python)
    check_flash_size(python, args.port)
    security_path = backup_dir / "security-prerestore.json"
    if security_path.exists():
        raise DeviceError("security prerestore evidence already exists")
    capture_security_summary(python, args.port, security_path)
    run_esptool(
        python,
        args.port,
        "write-flash",
        "--flash-mode",
        "keep",
        "--flash-freq",
        "keep",
        "--flash-size",
        "4MB",
        "0x0",
        str(full_flash),
    )
    run_esptool(python, args.port, "verify-flash", "0x0", str(full_flash))
    evidence_path = backup_dir / "full-flash-restored.json"
    evidence_path.write_text(
        json.dumps(
            {
                "efuse_operations_performed": False,
                "full_flash_verified": True,
                "kind": "rissokey-e000-full-flash-restore-evidence",
                "restored_at": datetime.now(UTC).isoformat(),
                "schema": 1,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(evidence_path, 0o600)
    print("restored and verified the complete pre-migration flash image")
    print("no eFuse was changed; the device remains in ROM download mode")


def add_transport_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--package-dir", required=True, type=Path)
    parser.add_argument("--esptool-python", required=True, type=Path)
    parser.add_argument("--port", required=True)
    parser.add_argument("--acknowledgement", required=True)


def add_backup_arguments(parser: argparse.ArgumentParser) -> None:
    add_transport_arguments(parser)
    parser.add_argument("--backup-dir", required=True, type=Path)


def add_disposable_arguments(parser: argparse.ArgumentParser) -> None:
    add_transport_arguments(parser)
    parser.add_argument("--evidence-dir", required=True, type=Path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Operate the reversible ESP32-S2 0xE000 migration. No subcommand "
            "burns eFuses or erases the credential store."
        )
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("backup", "apply", "restore"):
        add_backup_arguments(subparsers.add_parser(operation))
    for operation in ("apply-disposable", "restore-disposable"):
        add_disposable_arguments(subparsers.add_parser(operation))
    args = parser.parse_args()

    try:
        if not args.port.startswith("/dev/") or any(
            character.isspace() for character in args.port
        ):
            raise DeviceError("--port must be an explicit /dev path")
        if args.operation == "backup":
            backup_device(args)
        elif args.operation == "apply":
            apply_migration(args)
        elif args.operation == "restore":
            restore_backup(args)
        elif args.operation == "apply-disposable":
            apply_disposable_migration(args)
        else:
            restore_disposable_legacy(args)
    except (DeviceError, OSError, subprocess.CalledProcessError) as error:
        print(f"0xE000 device operation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
