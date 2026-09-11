#!/usr/bin/env python3
"""Compare read-only device image verification with two private signed images."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import struct
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import salpa_environment
from fido2_transport import open_connection

sys.dont_write_bytecode = True


class PreviewError(RuntimeError):
    pass


def decode_preview(response: bytes, slot: int) -> dict[str, object]:
    if len(response) != 64 or response[:4] != b"RKE1":
        raise PreviewError("firmware does not support RKE1 epoch preview")
    if response[4] != 0:
        raise PreviewError("device did not qualify the installed image")
    epoch, size = struct.unpack_from("<II", response, 8)
    sequences = list(struct.unpack_from("<II", response, 48))
    if (
        response[5] != slot or response[6] > 1 or response[7] != 0
        or response[56:] != bytes(8) or epoch > 16
        or size < 8192 or size > 0x1E0000 or size % 4096
        or any(value in (0, 0xFFFFFFFF) for value in sequences)
        or any((value - 1) % 2 != index for index, value in enumerate(sequences))
        or response[6] != int(sequences[1] > sequences[0])
    ):
        raise PreviewError("inconsistent epoch preview fields")
    return {
        "slot": slot,
        "running_slot": response[6],
        "secure_version": epoch,
        "signed_image_bytes": size,
        "signed_content_sha256": response[16:48].hex(),
        "valid_metadata_sequences": sequences,
    }


def read_preview(device, slot: int) -> dict[str, object]:
    cancel = threading.Event()
    timer = threading.Timer(30, cancel.set)
    timer.start()
    try:
        return decode_preview(device.call(0x51, bytes([0x12, slot]), event=cancel), slot)
    finally:
        timer.cancel()


def match_expected(record: dict[str, object], data: bytes) -> None:
    if (
        len(data) != record["signed_image_bytes"]
        or data[0] != 0xE9 or data[-4096] != 0xE7
        or int.from_bytes(data[36:40], "little") != record["secure_version"]
        or hashlib.sha256(data[:-4096]).hexdigest() != record["signed_content_sha256"]
    ):
        raise PreviewError("installed contents differ from the expected signed image")


def compare_images(device, images: list[bytes]) -> list[dict[str, object]]:
    if len(images) != 2:
        raise PreviewError("exactly two expected slot images are required")
    records = []
    for slot, data in enumerate(images):
        record = read_preview(device, slot)
        match_expected(record, data)
        records.append(record)
    for field in ("running_slot", "valid_metadata_sequences"):
        if records[0][field] != records[1][field]:
            raise PreviewError("OTA layout changed between image checks")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-reference", required=True, type=Path)
    parser.add_argument("--expected-slot0", required=True, type=Path)
    parser.add_argument("--expected-slot1", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    paths = (args.identity_reference, args.expected_slot0, args.expected_slot1, args.output)
    if any(path.resolve().is_relative_to(root) for path in paths):
        parser.error("device references, images and evidence must stay outside Git")
    os.umask(0o077)
    try:
        if version("fido2") != "2.2.1":
            raise PreviewError("python-fido2 2.2.1 is required")
        if args.output.exists() or args.output.is_symlink():
            raise PreviewError("output must be new")
        from fido2.hid import CtapHidDevice, list_descriptors

        identity = salpa_environment(json.loads(args.identity_reference.read_text()))
        matches = [
            d for d in list_descriptors()
            if d.vid == int(str(identity["SALPA_USB_VID"]), 0)
            and d.pid == int(str(identity["SALPA_USB_PID"]), 0)
            and d.serial_number == identity["SALPA_USB_SERIAL"]
        ]
        if len(matches) != 1:
            raise PreviewError("expected exactly one matching device")
        images = [args.expected_slot0.read_bytes(), args.expected_slot1.read_bytes()]
        device = CtapHidDevice(matches[0], open_connection(matches[0]))
        try:
            records = compare_images(device, images)
        finally:
            device.close()
        with args.output.open("x") as output:
            json.dump({
                "captured_at": datetime.now(UTC).isoformat(),
                "exact_usb_identity_matched": True,
                "device_verified_images_match_expected": True,
                "slots": records,
                "flash_or_efuse_write_requested": False,
                "boot_qualification_proven_by_this_command": False,
            }, output, indent=2)
            output.write("\n")
        print("PASS: both device-verified images match the expected signed contents")
        return 0
    except Exception as error:
        print(f"Epoch preview failed ({type(error).__name__}); no write requested", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
