#!/usr/bin/env python3
"""Install or stage the reversible signed A/B test on an ESP32-S2."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import is_within, sha256_file


FLASH_SIZE = 0x400000
BOOTLOADER_OFFSET = 0x1000
TABLE_OFFSET = 0xE000
OTADATA_OFFSET = 0xF000
DATA_END = 0x18000
OTA_0_OFFSET = 0x20000
OTA_1_OFFSET = 0x200000
OTA_SIZE = 0x1E0000
FIDO_STORE_OFFSET = 0x3E0000
FIDO_STORE_SIZE = 0x20000
SECTOR_SIZE = 0x1000
PACKAGE_MANIFEST = "rissokey-signed-ab-package.json"
ESPTOOL_VERSION = "5.4.0"
SECURITY_FIELDS = [
    "DIS_DOWNLOAD_MODE",
    "DIS_USB_DOWNLOAD_MODE",
    "ENABLE_SECURITY_DOWNLOAD",
    "SECURE_BOOT_EN",
    "SPI_BOOT_CRYPT_CNT",
]
IMAGE_FILES = {
    "failure": "failure-signed.bin",
    "success": "success-signed.bin",
    "untrusted": "untrusted-signed.bin",
}
PACKAGE_FILES = {
    "base-build.json",
    "base-signed.bin",
    "bootloader-build.json",
    "bootloader.bin",
    "failure-build.json",
    "failure-signed.bin",
    "partition-table.bin",
    "success-build.json",
    "success-signed.bin",
    "trusted-public-key.pem",
    "untrusted-signed.bin",
}
OTA_STATES = {
    0: "new",
    1: "pending-verify",
    2: "valid",
    3: "invalid",
    4: "aborted",
    0xFFFFFFFF: "undefined",
}


class DeviceError(RuntimeError):
    """A signed A/B physical-device gate failed."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise DeviceError(f"{label} must be a regular file: {path}")


def executable_file(path: Path, label: str) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise DeviceError(f"{label} must be an executable file: {path}")


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
    manifest = load_json(package_dir / PACKAGE_MANIFEST, "signed A/B package manifest")
    if (
        manifest.get("schema") != 1
        or manifest.get("kind") != "rissokey-signed-ab-package"
        or manifest.get("security_profile")
        not in {
            "wemos-s2-mini-non-strapping-up-test",
            "wemos-s2-mini-signed-ab-test",
        }
        or manifest.get("writes_fido_store") is not False
        or manifest.get("private_key_included") is not False
        or manifest.get("efuse_operations_performed") is not False
    ):
        raise DeviceError("unsupported or unsafe signed A/B package")
    if manifest.get("addresses") != {
        "bootloader": BOOTLOADER_OFFSET,
        "ota_0": OTA_0_OFFSET,
        "ota_1": OTA_1_OFFSET,
        "otadata": OTADATA_OFFSET,
        "partition_table": TABLE_OFFSET,
    }:
        raise DeviceError("signed A/B package has unexpected write addresses")
    layout = manifest.get("layout")
    if not isinstance(layout, dict) or (
        layout.get("fido_store_offset") != FIDO_STORE_OFFSET
        or layout.get("fido_store_size") != FIDO_STORE_SIZE
        or layout.get("ota_slot_size") != OTA_SIZE
    ):
        raise DeviceError("signed A/B package violates the flash layout")
    records = manifest.get("files")
    if not isinstance(records, dict):
        raise DeviceError("signed A/B package has no file records")
    if set(records) != PACKAGE_FILES:
        raise DeviceError("signed A/B package has an unexpected artifact set")
    actual_files = {
        path.name for path in package_dir.iterdir() if path.is_file() or path.is_symlink()
    }
    if actual_files != PACKAGE_FILES | {PACKAGE_MANIFEST}:
        raise DeviceError("signed A/B package directory has unrecorded artifacts")
    files: dict[str, Path] = {}
    for name, record in records.items():
        if not isinstance(name, str) or not isinstance(record, dict) or record.get("file") != name:
            raise DeviceError("invalid signed A/B package file record")
        path = (package_dir / name).resolve()
        if not is_within(path, package_dir) or path.parent != package_dir:
            raise DeviceError("signed A/B package file escapes its directory")
        regular_file(path, "signed A/B package file")
        if record.get("size") != path.stat().st_size or record.get("sha256") != sha256_file(path):
            raise DeviceError(f"signed A/B package file hash mismatch: {name}")
        files[name] = path
    if files["partition-table.bin"].stat().st_size != 0xC00:
        raise DeviceError("partition table has an unexpected size")
    if files["bootloader.bin"].stat().st_size > TABLE_OFFSET - BOOTLOADER_OFFSET:
        raise DeviceError("bootloader overlaps the partition table")
    for name in ("base-signed.bin", *IMAGE_FILES.values()):
        if files[name].stat().st_size > OTA_SIZE:
            raise DeviceError(f"{name} exceeds an OTA slot")
    return manifest, files


def tool_version(python: Path) -> None:
    executable_file(python, "Espressif Python interpreter")
    result = subprocess.run(
        [str(python), "-c", "import esptool; print(esptool.__version__)"],
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip() != ESPTOOL_VERSION:
        raise DeviceError(f"esptool must be exactly {ESPTOOL_VERSION}")


def run_esptool(python: Path, port: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
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
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def check_flash_size(python: Path, port: str) -> None:
    if re.search(r"Detected flash size:\s*4MB\b", run_esptool(python, port, "flash-id").stdout) is None:
        raise DeviceError("device must report exactly 4 MB of flash")


def capture_security_summary(python: Path, port: str, output: Path) -> None:
    subprocess.run(
        [
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
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    os.chmod(output, 0o600)
    summary = load_json(output, "security preflight")
    if set(summary) != set(SECURITY_FIELDS):
        raise DeviceError("security preflight omitted required eFuse fields")
    for name in SECURITY_FIELDS:
        record = summary.get(name)
        if not isinstance(record, dict) or not record.get("readable"):
            raise DeviceError(f"security preflight cannot read {name}")
    if summary["SECURE_BOOT_EN"].get("value") is not False:
        raise DeviceError("Secure Boot is already enabled; reversible A/B test is blocked")
    crypt = summary["SPI_BOOT_CRYPT_CNT"]
    if crypt.get("raw_value") != "0x0" or crypt.get("value") != "Disable":
        raise DeviceError("flash encryption is not disabled")
    for name in ("DIS_DOWNLOAD_MODE", "DIS_USB_DOWNLOAD_MODE", "ENABLE_SECURITY_DOWNLOAD"):
        if summary[name].get("value") is not False:
            raise DeviceError("ROM download recovery is not fully available")


def temporary_root() -> Path:
    raw = os.environ.get("TMPDIR")
    if not raw:
        raise DeviceError("TMPDIR is required for ephemeral device readback")
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise DeviceError("TMPDIR is not available")
    return path


def read_region(python: Path, port: str, offset: int, size: int) -> bytes:
    with tempfile.TemporaryDirectory(prefix="rissokey-ab-read-", dir=temporary_root()) as directory:
        output = Path(directory) / "region.bin"
        run_esptool(
            python, port, "read-flash", "--no-progress", hex(offset), hex(size), str(output)
        )
        data = output.read_bytes()
        if len(data) != size:
            raise DeviceError(f"short readback at 0x{offset:x}")
        return data


def write_and_verify(python: Path, port: str, offset: int, artifact: Path) -> None:
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


def erase_and_verify(python: Path, port: str, offset: int, size: int) -> None:
    run_esptool(python, port, "erase-region", hex(offset), hex(size))
    if read_region(python, port, offset, size) != b"\xff" * size:
        raise DeviceError(f"flash region at 0x{offset:x} did not erase cleanly")


def ensure_evidence_dir(path: Path, root: Path) -> None:
    if is_within(path, root):
        raise DeviceError("device evidence must stay outside the repository")
    if path.exists() and any(path.iterdir()):
        raise DeviceError("evidence directory must be new or empty")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def write_evidence(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def ota_crc(sequence: int) -> int:
    return binascii.crc32(struct.pack("<I", sequence), 0xFFFFFFFF) & 0xFFFFFFFF


def decode_entry(data: bytes) -> dict[str, object]:
    if len(data) != 32:
        raise DeviceError("invalid otadata entry size")
    sequence, state, crc = struct.unpack_from("<I20xII", data)
    selectable = (
        sequence != 0xFFFFFFFF
        and state not in (3, 4)
        and crc == ota_crc(sequence)
    )
    return {
        "crc_valid": sequence != 0xFFFFFFFF and crc == ota_crc(sequence),
        "selectable": selectable,
        "sequence": sequence,
        "slot": (sequence - 1) % 2 if sequence not in (0, 0xFFFFFFFF) else None,
        "state": state,
        "state_name": OTA_STATES.get(state, "unknown"),
    }


def read_otadata(python: Path, port: str) -> tuple[list[dict[str, object]], bytes]:
    data = read_region(python, port, OTADATA_OFFSET, 2 * SECTOR_SIZE)
    return [decode_entry(data[:32]), decode_entry(data[SECTOR_SIZE : SECTOR_SIZE + 32])], data


def active_entry(entries: list[dict[str, object]]) -> int | None:
    selectable = [index for index, entry in enumerate(entries) if entry["selectable"]]
    if not selectable:
        return None
    return max(selectable, key=lambda index: int(entries[index]["sequence"]))


def next_sequence(current: int, target_slot: int) -> int:
    candidate = (target_slot + 1) % 2
    while current > candidate:
        candidate += 2
    if candidate == 0:
        candidate = 2
    return candidate


def make_otadata_sector(sequence: int) -> bytes:
    sector = bytearray(b"\xff" * SECTOR_SIZE)
    struct.pack_into("<I", sector, 0, sequence)
    struct.pack_into("<I", sector, 24, 0)
    struct.pack_into("<I", sector, 28, ota_crc(sequence))
    return bytes(sector)


def preflight(args: argparse.Namespace) -> tuple[Path, dict[str, object], dict[str, Path], Path]:
    root = repository_root()
    package_dir = args.package_dir.expanduser().resolve()
    evidence_dir = args.evidence_dir.expanduser().resolve()
    # Keep the virtual-environment interpreter instead of resolving its symlink
    # to a base Python with a potentially different esptool installation.
    python = args.esptool_python.expanduser().absolute()
    manifest, files = verify_package(package_dir)
    tool_version(python)
    ensure_evidence_dir(evidence_dir, root)
    check_flash_size(python, args.port)
    capture_security_summary(python, args.port, evidence_dir / "security-preflight.json")
    return python, manifest, files, evidence_dir


def install(args: argparse.Namespace) -> None:
    if args.acknowledgement != "INSTALL_SIGNED_AB_TEST_WITHOUT_BACKUP":
        raise DeviceError("install acknowledgement is missing or incorrect")
    python, manifest, files, evidence_dir = preflight(args)
    store_digest = hashlib.sha256(
        read_region(python, args.port, FIDO_STORE_OFFSET, FIDO_STORE_SIZE)
    ).hexdigest()
    erase_and_verify(python, args.port, BOOTLOADER_OFFSET, TABLE_OFFSET - BOOTLOADER_OFFSET)
    erase_and_verify(python, args.port, OTADATA_OFFSET, DATA_END - OTADATA_OFFSET)
    erase_and_verify(python, args.port, OTA_0_OFFSET, FIDO_STORE_OFFSET - OTA_0_OFFSET)
    write_and_verify(python, args.port, OTA_0_OFFSET, files["base-signed.bin"])
    write_and_verify(python, args.port, TABLE_OFFSET, files["partition-table.bin"])
    write_and_verify(python, args.port, BOOTLOADER_OFFSET, files["bootloader.bin"])
    if hashlib.sha256(read_region(python, args.port, FIDO_STORE_OFFSET, FIDO_STORE_SIZE)).hexdigest() != store_digest:
        raise DeviceError("credential storage changed during signed A/B installation")
    write_evidence(
        evidence_dir / "installed.json",
        {
            "credential_store_preserved": True,
            "efuse_operations_performed": False,
            "full_flash_backup_captured": False,
            "installed_at": datetime.now(UTC).isoformat(),
            "kind": "rissokey-signed-ab-install-evidence",
            "package_manifest_sha256": sha256_file(args.package_dir.expanduser().resolve() / PACKAGE_MANIFEST),
            "schema": 1,
            "source_commit": manifest.get("source_commit"),
            "write_order_completed": [
                "erase_bootloader_region",
                "erase_otadata_nvs_phy",
                "erase_ota_slots",
                "base_signed_image",
                "partition_table",
                "bootloader",
            ],
        },
    )
    print("installed and verified the signed A/B base image")
    print("credential storage was unchanged; no eFuse was changed")
    print("the device remains in ROM download mode for an explicit reset")


def stage(args: argparse.Namespace) -> None:
    expected_ack = f"STAGE_SIGNED_AB_{args.image.upper()}"
    if args.acknowledgement != expected_ack:
        raise DeviceError(f"stage acknowledgement must be {expected_ack}")
    python, manifest, files, evidence_dir = preflight(args)
    entries, _ = read_otadata(python, args.port)
    active = active_entry(entries)
    if active is None:
        raise DeviceError("no valid active A/B image; boot the installed base image first")
    current = entries[active]
    if current["state"] != 2:
        raise DeviceError("active image is not VALID; reset once to complete rollback first")
    current_slot = int(current["slot"])
    target_slot = 1 - current_slot
    target_offset = (OTA_0_OFFSET, OTA_1_OFFSET)[target_slot]
    sequence = next_sequence(int(current["sequence"]), target_slot)
    image = files[IMAGE_FILES[args.image]]
    store_digest = hashlib.sha256(
        read_region(python, args.port, FIDO_STORE_OFFSET, FIDO_STORE_SIZE)
    ).hexdigest()

    erase_and_verify(python, args.port, target_offset, OTA_SIZE)
    write_and_verify(python, args.port, target_offset, image)
    if hashlib.sha256(read_region(python, args.port, target_offset, image.stat().st_size)).hexdigest() != sha256_file(image):
        raise DeviceError("staged OTA image readback mismatch")
    with tempfile.TemporaryDirectory(prefix="rissokey-ab-entry-", dir=temporary_root()) as directory:
        sector_path = Path(directory) / "otadata-sector.bin"
        sector_path.write_bytes(make_otadata_sector(sequence))
        write_and_verify(
            python,
            args.port,
            OTADATA_OFFSET + (1 - active) * SECTOR_SIZE,
            sector_path,
        )
    if hashlib.sha256(read_region(python, args.port, FIDO_STORE_OFFSET, FIDO_STORE_SIZE)).hexdigest() != store_digest:
        raise DeviceError("credential storage changed while staging the A/B image")
    final_entries, _ = read_otadata(python, args.port)
    write_evidence(
        evidence_dir / "staged.json",
        {
            "credential_store_preserved": True,
            "efuse_operations_performed": False,
            "image": args.image,
            "image_sha256": sha256_file(image),
            "kind": "rissokey-signed-ab-stage-evidence",
            "otadata_after": final_entries,
            "package_manifest_sha256": sha256_file(args.package_dir.expanduser().resolve() / PACKAGE_MANIFEST),
            "schema": 1,
            "source_commit": manifest.get("source_commit"),
            "staged_at": datetime.now(UTC).isoformat(),
            "target_slot": target_slot,
        },
    )
    print(f"staged and verified the signed A/B {args.image} image in ota_{target_slot}")
    print("credential storage was unchanged; no eFuse was changed")
    print("the device remains in ROM download mode for an explicit reset")


def status(args: argparse.Namespace) -> None:
    python, manifest, _, evidence_dir = preflight(args)
    entries, _ = read_otadata(python, args.port)
    active = active_entry(entries)
    write_evidence(
        evidence_dir / "status.json",
        {
            "active_entry": active,
            "active_slot": entries[active]["slot"] if active is not None else None,
            "captured_at": datetime.now(UTC).isoformat(),
            "efuse_operations_performed": False,
            "kind": "rissokey-signed-ab-status-evidence",
            "otadata": entries,
            "package_manifest_sha256": sha256_file(args.package_dir.expanduser().resolve() / PACKAGE_MANIFEST),
            "schema": 1,
            "source_commit": manifest.get("source_commit"),
        },
    )
    print(json.dumps({"active_entry": active, "entries": entries}, sort_keys=True))
    print("read-only status captured; no flash or eFuse operation was performed")


def add_common(parser: argparse.ArgumentParser, *, acknowledgement: bool = True) -> None:
    parser.add_argument("--package-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--esptool-python", required=True, type=Path)
    parser.add_argument("--port", required=True)
    if acknowledgement:
        parser.add_argument("--acknowledgement", required=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Operate the reversible signed A/B ESP32-S2 test; never burns eFuses."
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    add_common(subparsers.add_parser("install"))
    stage_parser = subparsers.add_parser("stage")
    add_common(stage_parser)
    stage_parser.add_argument("--image", choices=sorted(IMAGE_FILES), required=True)
    add_common(subparsers.add_parser("status"), acknowledgement=False)
    args = parser.parse_args()

    try:
        if not args.port.startswith("/dev/") or any(character.isspace() for character in args.port):
            raise DeviceError("--port must be an explicit /dev path")
        if args.operation == "install":
            install(args)
        elif args.operation == "stage":
            stage(args)
        else:
            status(args)
    except (DeviceError, OSError, subprocess.CalledProcessError) as error:
        print(f"signed A/B device operation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
