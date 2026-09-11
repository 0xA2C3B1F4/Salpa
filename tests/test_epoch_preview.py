from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "epoch_preview", ROOT / "tools/fido2-epoch-preview.py"
)
PREVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREVIEW)


def fixture(slot: int = 0, sequences: tuple[int, int] = (3, 4)) -> tuple[bytes, bytes]:
    image = bytearray(8192)
    image[0] = 0xE9
    image[4096] = 0xE7
    struct.pack_into("<I", image, 36, 4)
    response = bytearray(64)
    response[:4] = b"RKE1"
    response[5] = slot
    response[6] = int(sequences[1] > sequences[0])
    struct.pack_into("<II", response, 8, 4, len(image))
    response[16:48] = hashlib.sha256(image[:4096]).digest()
    struct.pack_into("<II", response, 48, *sequences)
    return bytes(response), bytes(image)


class EpochPreviewTests(unittest.TestCase):
    def test_both_image_checks_use_only_the_read_only_vendor_request(self):
        class Device:
            def __init__(self):
                self.requests = []

            def call(self, command, payload, **kwargs):
                self.requests.append((command, payload))
                return fixture(payload[1])[0]

        device = Device()
        image = fixture()[1]
        records = PREVIEW.compare_images(device, [image, image])
        self.assertEqual(len(records), 2)
        self.assertEqual(device.requests, [(0x51, b"\x12\0"), (0x51, b"\x12\x01")])

    def test_inconsistent_and_failed_responses_are_rejected(self):
        response, _ = fixture()
        for offset, value in [
            (0, 0), (4, 1), (5, 1), (6, 2), (6, 0), (7, 1),
            (8, 17), (12, 1), (48, 0), (48, 2), (52, 3), (63, 1),
        ]:
            changed = bytearray(response)
            changed[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(PREVIEW.PreviewError):
                PREVIEW.decode_preview(bytes(changed), 0)
        for invalid in [b"", response[:-1], response + b"\0"]:
            with self.assertRaises(PREVIEW.PreviewError):
                PREVIEW.decode_preview(invalid, 0)

    def test_wrong_image_or_epoch_cannot_match_the_device_record(self):
        response, image = fixture()
        record = PREVIEW.decode_preview(response, 0)
        PREVIEW.match_expected(record, image)
        for offset in [0, 36, 500, 4096]:
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(PREVIEW.PreviewError):
                PREVIEW.match_expected(record, bytes(changed))
        for invalid in [b"", image[:-1], image + b"\0"]:
            with self.assertRaises(PREVIEW.PreviewError):
                PREVIEW.match_expected(record, invalid)

    def test_layout_changes_between_slot_checks_are_rejected(self):
        class Device:
            def call(self, command, payload, **kwargs):
                return fixture(payload[1], (3, 4) if payload[1] == 0 else (5, 4))[0]

        image = fixture()[1]
        with self.assertRaises(PREVIEW.PreviewError):
            PREVIEW.compare_images(Device(), [image, image])

    def test_full_partition_extent_is_supported_but_overflow_is_not(self):
        response = bytearray(fixture()[0])
        struct.pack_into("<I", response, 12, 0x1E0000)
        self.assertEqual(PREVIEW.decode_preview(bytes(response), 0)["signed_image_bytes"], 0x1E0000)
        for invalid in [0, 4096, 0x1E0001, 0x1E1000, 0xFFFFFFFF]:
            struct.pack_into("<I", response, 12, invalid)
            with self.assertRaises(PREVIEW.PreviewError):
                PREVIEW.decode_preview(bytes(response), 0)


if __name__ == "__main__":
    unittest.main()
