from __future__ import annotations

from datetime import UTC, datetime, timedelta
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "maintenance", ROOT / "tools/fido2-epoch-maintenance.py"
)
MAINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAINT)


def plan():
    data = bytearray([1] * 164)
    data[:8] = b"RKMPLAN1"
    data[104:128] = bytes(24)
    data[160:] = bytes([4, 1, 0, 0])
    return MAINT.decode_plan(bytes(data))


class MaintenanceTests(unittest.TestCase):
    def test_device_failure_retains_only_status_and_never_becomes_success(self):
        response = bytearray(64)
        response[:4] = b"RKM1"
        for status in (1, 5, 6, 8, 255):
            response[4] = status
            with self.subTest(status=status):
                with self.assertRaises(MAINT.DeviceMaintenanceError) as failure:
                    MAINT.decode_response(response, plan(), 0x14)
                self.assertEqual(failure.exception.status, status)
                self.assertIsNone(failure.exception.transaction_status)
        response[4:6] = bytes([6, 3])
        with self.assertRaises(MAINT.DeviceMaintenanceError) as failure:
            MAINT.decode_response(response, plan(), 0x14)
        self.assertEqual(failure.exception.transaction_status, 3)
        for malformed in (response[:-1], b"FAIL" + response[4:]):
            with self.assertRaises(MAINT.MaintenanceError) as failure:
                MAINT.decode_response(malformed, plan(), 0x14)
            self.assertNotIsInstance(failure.exception, MAINT.DeviceMaintenanceError)

    def test_response_must_match_the_exact_plan_counter_and_layout(self):
        scope = plan()
        response = bytearray(64)
        response[:4] = b"RKM1"
        response[5] = 4
        response[6] = 1
        response[8:40] = bytes.fromhex(scope["plan_sha256"])
        struct.pack_into("<IIIHH", response, 40, 7, 8, 80_000_000, 0, 15)
        response[56] = 0x13
        result = MAINT.decode_response(response, scope, 0x13)
        self.assertEqual(result["target_epoch"], 4)
        for index in [0, 4, 5, 6, 7, 8, 40, 44, 48, 52, 54, 56, 63]:
            changed = bytearray(response)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(MAINT.MaintenanceError):
                MAINT.decode_response(changed, scope, 0x13)
        for data in [b"", response[:-1], response + b"\0"]:
            with self.assertRaises(MAINT.MaintenanceError):
                MAINT.decode_response(data, scope, 0x13)

    def test_approval_is_recent_explicit_and_bound_to_every_input(self):
        now = datetime(2026, 9, 6, tzinfo=UTC)
        binding = {
            "plan_sha256": "1" * 64, "target_epoch": 4, "before_raw": 0,
            "slot_content_sha256": ["2" * 64, "3" * 64],
            "usb_identity_reference_sha256": "4" * 64,
        }
        approval = {"approved": True, "operation": "counter-only-programming",
                    "approved_at": now.isoformat(), **binding}
        self.assertTrue(MAINT.approval_matches(approval, binding, now))
        for field in binding:
            changed = dict(approval)
            changed[field] = None
            self.assertFalse(MAINT.approval_matches(changed, binding, now))
        for age in [-1, 301]:
            changed = dict(approval, approved_at=(now - timedelta(seconds=age)).isoformat())
            self.assertFalse(MAINT.approval_matches(changed, binding, now))
        for change in [{"approved": False}, {"approved": 1}, {"operation": "rehearse"},
                       {"approved_at": "invalid"}, {"approved_at": "2026-09-06"}]:
            self.assertFalse(MAINT.approval_matches(dict(approval, **change), binding, now))

    def test_cli_raw_bitmap_is_not_interpreted_as_an_epoch_number(self):
        data = bytearray([1] * 164)
        data[:8] = b"RKMPLAN1"
        data[104:128] = bytes(24)
        data[160:] = bytes([4, 1, 0, 0])
        struct.pack_into("<I", data, 120, 4 << 11)
        self.assertEqual(MAINT.decode_plan(data)["before_raw"].bit_count(), 1)
        struct.pack_into("<I", data, 120, 15 << 11)
        with self.assertRaises(MAINT.MaintenanceError):
            MAINT.decode_plan(data)


if __name__ == "__main__":
    unittest.main()
