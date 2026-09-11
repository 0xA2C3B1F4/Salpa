#!/usr/bin/env python3
"""Read selected non-secret hardware policy fields through normal USB FIDO."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
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

POLICY_FLAGS = (
    "secure_boot_enabled",
    "rom_download_disabled",
    "usb_rom_download_disabled",
    "restricted_rom_download_enabled",
    "usb_peripheral_disabled",
    "hardware_jtag_disabled",
)


class StatusError(RuntimeError):
    pass


def decode_status(response: bytes) -> dict[str, object]:
    if len(response) != 32 or response[:4] != b"RKS1":
        raise StatusError("firmware does not support the RKS1 security status")
    raw = struct.unpack_from("<H", response, 4)[0]
    write_disable, flags = struct.unpack_from("<II", response, 8)
    if (
        response[6] != raw.bit_count()
        or response[7] != 0
        or response[21:24] != bytes(3)
        or response[28:32] != bytes(4)
        or flags & ~0x3F
        or response[16] > 7
        or response[17] > 0x7F
        or response[18] > 7
    ):
        raise StatusError("inconsistent or unsupported security status fields")
    return {
        "secure_version_raw": raw,
        "hardware_secure_version": raw.bit_count(),
        "security_epoch_bits_remaining": 16 - raw.bit_count(),
        "write_disable_raw": write_disable,
        "rom_and_secure_version_group_write_protected": bool(write_disable & (1 << 18)),
        **{name: bool(flags & (1 << bit)) for bit, name in enumerate(POLICY_FLAGS)},
        "flash_crypt_count_raw": response[16],
        "flash_encryption_enabled": bool(response[16].bit_count() & 1),
        "read_disable_raw": response[17],
        "revoked_root_slots_mask": response[18],
        "chip_revision_major": response[19],
        "chip_revision_minor": response[20],
        "application_secure_version": struct.unpack_from("<I", response, 24)[0],
    }


def read_status(device) -> dict[str, object]:
    cancel = threading.Event()
    timer = threading.Timer(5, cancel.set)
    timer.start()
    try:
        return decode_status(device.call(0x51, b"\x11", event=cancel))
    finally:
        timer.cancel()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-reference", type=Path, required=True,
                        help="private JSON with SALPA_USB_VID/PID/SERIAL fields")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if any(path.resolve().is_relative_to(root)
           for path in (args.identity_reference, args.output)):
        parser.error("private references and device evidence must stay outside Git")
    os.umask(0o077)
    try:
        if version("fido2") != "2.2.1":
            raise StatusError("python-fido2 2.2.1 is required")
        from fido2.hid import CtapHidDevice, list_descriptors

        identity = salpa_environment(json.loads(args.identity_reference.read_text()))
        matches = [d for d in list_descriptors()
                   if d.vid == int(str(identity["SALPA_USB_VID"]), 0)
                   and d.pid == int(str(identity["SALPA_USB_PID"]), 0)
                   and d.serial_number == identity["SALPA_USB_SERIAL"]]
        if len(matches) != 1:
            raise StatusError("expected exactly one matching device")
        device = CtapHidDevice(matches[0], open_connection(matches[0]))
        try:
            result = read_status(device)
        finally:
            device.close()
        record = {"schema": 1, "captured_at": datetime.now(UTC).isoformat(),
                  "device_writes_requested": False, "security_status": result}
        with args.output.open("x") as output:
            json.dump(record, output, indent=2)
            output.write("\n")
    except StatusError as error:
        print(f"security status failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Driver exceptions can include a private USB serial or path.
        print("security status failed; check the private identity, USB and output path",
              file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
