from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "security_status", ROOT / "tools/fido2-security-status.py"
)
STATUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATUS)


def reply(raw: int = 15) -> bytes:
    data = bytearray(32)
    data[:4] = b"RKS1"
    struct.pack_into("<H", data, 4, raw)
    data[6] = raw.bit_count()
    struct.pack_into("<II", data, 8, 0x01800305, 0x23)
    data[16:21] = bytes([7, 1, 6, 1, 0])
    struct.pack_into("<I", data, 24, 4)
    return bytes(data)


class SecurityStatusTests(unittest.TestCase):
    def test_epoch_is_population_count_including_sparse_and_exhausted_fields(self):
        for raw in (0, 7, 15, 0x8000, 0xFFFF):
            with self.subTest(raw=raw):
                decoded = STATUS.decode_status(reply(raw))
                self.assertEqual(decoded["hardware_secure_version"], raw.bit_count())
                self.assertEqual(decoded["security_epoch_bits_remaining"], 16 - raw.bit_count())
                self.assertTrue(decoded["rom_download_disabled"])
                self.assertFalse(decoded["usb_peripheral_disabled"])
                self.assertFalse(decoded["rom_and_secure_version_group_write_protected"])

    def test_unknown_or_inconsistent_fields_are_rejected(self):
        for offset, value in [(0, 0), (6, 0), (7, 1), (15, 0x80),
                              (16, 8), (17, 0x80), (18, 8), (21, 1), (31, 1)]:
            data = bytearray(reply())
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(STATUS.StatusError):
                STATUS.decode_status(bytes(data))
        for size in (0, 1, 21, 31, 33):
            with self.assertRaises(STATUS.StatusError):
                STATUS.decode_status(reply()[:size] if size < 32 else reply() + b"\0")

    def test_usb_request_is_only_the_read_only_status_command(self):
        class Device:
            def call(self, command, payload, **kwargs):
                self.request = (command, payload)
                return reply()
        device = Device()
        STATUS.read_status(device)
        self.assertEqual(device.request, (0x51, b"\x11"))


if __name__ == "__main__":
    unittest.main()
