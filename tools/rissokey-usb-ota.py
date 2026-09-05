#!/usr/bin/env python3
"""Install a signed ESP32-S2 RissoKey image through CTAPHID vendor command 0x51."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

FIDO2_VERSION = "2.2.1"
VENDOR_COMMAND = 0x51
PROTOCOL_VERSION = 1
MAX_WRITE_CHUNK = 992
OTA_SLOT_SIZE = 0x1E0000
SIGNATURE_SECTOR_SIZE = 0x1000
ESP_IMAGE_MAGIC = 0xE9
ESP32S2_CHIP_ID = 2
APP_DESCRIPTOR_MAGIC = 0xABCD5432

OP_INFO = 0
OP_BEGIN = 1
OP_WRITE = 2
OP_ADVANCE = 3

STATUS_NAMES = {
    0: "ok",
    1: "user-presence-required",
    2: "invalid-request",
    3: "invalid-state",
    4: "session-mismatch",
    5: "out-of-order",
    6: "image-size",
    7: "flash",
    8: "hash-mismatch",
    9: "signature",
    10: "rollback",
    11: "version-mismatch",
    12: "active-slot-changed",
}

PHASE_NAMES = {
    0: "idle",
    1: "erasing",
    2: "receiving",
    3: "verifying",
    4: "activated",
    5: "failed",
}


class UpdateError(RuntimeError):
    """The image or device violated the signed-update contract."""


@dataclass(frozen=True)
class ImageMetadata:
    size: int
    sha256: bytes
    secure_version: int
    version: str


@dataclass(frozen=True)
class DeviceStatus:
    status: int
    protocol: int
    phase: int
    target_slot: int
    session_id: int
    completed: int
    total: int
    current_secure_version: int
    current_version: str


def usb_id(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("USB ID must fit in 16 bits")
    return parsed


def load_image(path: Path) -> tuple[bytes, ImageMetadata]:
    if not path.is_file() or path.is_symlink():
        raise UpdateError(f"image must be a regular file: {path}")
    image = path.read_bytes()
    if (
        len(image) < SIGNATURE_SECTOR_SIZE * 2
        or len(image) > OTA_SLOT_SIZE
        or len(image) % SIGNATURE_SECTOR_SIZE != 0
    ):
        raise UpdateError("signed image size does not fit one aligned OTA slot")
    if image[0] != ESP_IMAGE_MAGIC or not 1 <= image[1] <= 16:
        raise UpdateError("image has an invalid ESP application header")
    if struct.unpack_from("<H", image, 12)[0] != ESP32S2_CHIP_ID:
        raise UpdateError("image is not for ESP32-S2")
    if struct.unpack_from("<I", image, 32)[0] != APP_DESCRIPTOR_MAGIC:
        raise UpdateError("image has no valid ESP application descriptor")
    secure_version = struct.unpack_from("<I", image, 36)[0]
    version_field = image[48:80]
    version_bytes = version_field.split(b"\0", 1)[0]
    if not version_bytes or len(version_bytes) > 31:
        raise UpdateError("image has no bounded NUL-terminated version")
    try:
        image_version = version_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise UpdateError("image version is not UTF-8") from error
    return image, ImageMetadata(
        size=len(image),
        sha256=hashlib.sha256(image).digest(),
        secure_version=secure_version,
        version=image_version,
    )


def decode_status(reply: bytes) -> DeviceStatus:
    if len(reply) < 21:
        raise UpdateError("device returned a truncated update response")
    version_length = reply[20]
    if version_length == 0 or version_length > 31 or len(reply) != 21 + version_length:
        raise UpdateError("device returned an invalid version field")
    try:
        current_version = reply[21:].decode("utf-8")
    except UnicodeDecodeError as error:
        raise UpdateError("device returned a non-UTF-8 version") from error
    status = DeviceStatus(
        status=reply[0],
        protocol=reply[1],
        phase=reply[2],
        target_slot=reply[3],
        session_id=struct.unpack_from("<I", reply, 4)[0],
        completed=struct.unpack_from("<I", reply, 8)[0],
        total=struct.unpack_from("<I", reply, 12)[0],
        current_secure_version=struct.unpack_from("<I", reply, 16)[0],
        current_version=current_version,
    )
    if status.protocol != PROTOCOL_VERSION:
        raise UpdateError(f"unsupported device update protocol {status.protocol}")
    if status.status not in STATUS_NAMES or status.phase not in PHASE_NAMES:
        raise UpdateError("device returned an unknown update status")
    return status


def require_ok(status: DeviceStatus, operation: str) -> None:
    if status.status != 0:
        name = STATUS_NAMES[status.status]
        raise UpdateError(f"{operation} failed: {name}, phase={PHASE_NAMES[status.phase]}")


def progress(phase: str, completed: int, total: int) -> None:
    percent = 100 if total == 0 else min(100, completed * 100 // total)
    print(f"\r{phase}: {completed}/{total} bytes ({percent:3d}%)", end="", flush=True)
    if completed >= total:
        print()


def open_device(vid: int, pid: int) -> Any:
    from fido2.hid import CtapHidDevice, list_descriptors, open_connection

    matches = [
        descriptor
        for descriptor in list_descriptors()
        if descriptor.vid == vid and descriptor.pid == pid
    ]
    if len(matches) != 1:
        raise UpdateError(f"expected one matching FIDO HID device, found {len(matches)}")
    return CtapHidDevice(matches[0], open_connection(matches[0]))


def call(device: Any, request: bytes, operation: str) -> DeviceStatus:
    status = decode_status(device.call(VENDOR_COMMAND, request))
    require_ok(status, operation)
    return status


def install(device: Any, image: bytes, metadata: ImageMetadata) -> None:
    info = call(device, bytes([OP_INFO]), "device info")
    print(
        f"device version={info.current_version} secure_version={info.current_secure_version}; "
        f"image version={metadata.version} secure_version={metadata.secure_version}"
    )
    print(f"image sha256={metadata.sha256.hex()} size={metadata.size}")
    if metadata.secure_version < info.current_secure_version:
        raise UpdateError("host refused a secure-version rollback before requesting presence")

    version_bytes = metadata.version.encode("utf-8")
    begin = (
        bytes([OP_BEGIN, PROTOCOL_VERSION])
        + struct.pack("<I", metadata.size)
        + metadata.sha256
        + struct.pack("<I", metadata.secure_version)
        + bytes([len(version_bytes)])
        + version_bytes
    )
    prompted = False

    def keepalive(_status: object) -> None:
        nonlocal prompted
        if not prompted:
            print("Press and release the RissoKey update button to approve this image.", flush=True)
            prompted = True

    status = decode_status(
        device.call(VENDOR_COMMAND, begin, on_keepalive=keepalive)
    )
    require_ok(status, "begin")
    if status.phase != 1 or status.session_id == 0 or status.total != metadata.size:
        raise UpdateError("device did not create the expected erase session")
    session = struct.pack("<I", status.session_id)

    while status.phase == 1:
        status = call(device, bytes([OP_ADVANCE]) + session, "erase")
        erase_completed = status.total if status.phase == 2 else status.completed
        progress("erase", erase_completed, status.total)
    if status.phase != 2 or status.completed != 0:
        raise UpdateError("device did not enter the receiving phase after erase")

    offset = 0
    while offset < len(image):
        count = min(MAX_WRITE_CHUNK, len(image) - offset)
        request = (
            bytes([OP_WRITE])
            + session
            + struct.pack("<I", offset)
            + image[offset : offset + count]
        )
        status = call(device, request, "write")
        offset += count
        if status.phase != 2 or status.completed != offset:
            raise UpdateError("device write progress diverged from the host offset")
        progress("write", status.completed, status.total)

    while status.phase in (2, 3):
        status = call(device, bytes([OP_ADVANCE]) + session, "verify and activate")
        progress("verify", status.completed, status.total)
    if status.phase != 4 or status.target_slot not in (0, 1):
        raise UpdateError("device did not activate the verified inactive slot")
    print(
        f"verified and selected inactive slot ota_{status.target_slot}; "
        "unplug and reconnect to boot it"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vid", type=usb_id)
    parser.add_argument("pid", type=usb_id)
    parser.add_argument("image", type=Path)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and describe the image without opening a USB device",
    )
    args = parser.parse_args()
    try:
        image, metadata = load_image(args.image.expanduser().resolve())
        if args.dry_run:
            print(
                f"valid ESP32-S2 image: version={metadata.version} "
                f"secure_version={metadata.secure_version} size={metadata.size} "
                f"sha256={metadata.sha256.hex()}"
            )
            return 0
        try:
            installed_fido2 = package_version("fido2")
        except PackageNotFoundError as error:
            raise UpdateError(f"python-fido2 {FIDO2_VERSION} is required") from error
        if installed_fido2 != FIDO2_VERSION:
            raise UpdateError(
                f"this tool requires python-fido2 {FIDO2_VERSION}, found {installed_fido2}"
            )
        device = open_device(args.vid, args.pid)
        try:
            install(device, image, metadata)
        finally:
            device.close()
    except (OSError, UpdateError) as error:
        print(f"USB update failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
