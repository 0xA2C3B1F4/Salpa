"""Public, synthetic PMS fixtures; no device connection or firmware signing."""

import copy
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from memory_protection import decode_status, parse_sections, validate_handler, validate_layout


SYMBOLS = {
    "_salpa_pms_iram_end": 0x40028000,
    "_data_start": 0x3FFB8000,
    "_stack_end": 0x3FFC0000,
    "_stack_start": 0x3FFDE000,
    "salpa::platform::memory_protection::hardware::__esp_hal_internal_memory_fault": 0x40025000,
}
SECTIONS = [
    {"name": ".rwtext", "address": 0x40024400, "size": 0x1000,
     "flags": {"ALLOC", "CODE", "READONLY"}},
    {"name": ".vectors", "address": 0x40024000, "size": 0x400,
     "flags": {"ALLOC", "CODE", "READONLY"}},
    {"name": ".data", "address": 0x3FFB8000, "size": 0x1000,
     "flags": {"ALLOC", "DATA"}},
    {"name": ".stack", "address": 0x3FFC0000, "size": 0x1E000,
     "flags": {"ALLOC"}},
]


def status_fixture():
    # Published register values for the fixed minimum split, not device data.
    return bytearray(b"RKMP\x01\x0f\x0f\x00" + struct.pack(
        "<10I", 0x40028000, 0x3FFB8000, 0x6DB, 0x6A000, 0,
        0x1AE00055, 0x7800, 0, 0x1B000, 0,
    ) + bytes(16))


def decode(reply):
    return decode_status(reply, iram_end=0x40028000, data_start=0x3FFB8000)


class MemoryProtectionTests(unittest.TestCase):
    def test_valid_readback_does_not_claim_hardware_fault_test(self):
        result = decode(status_fixture())
        self.assertTrue(result["all_banks_locked"])
        self.assertFalse(result["hardware_fault_enforcement_tested"])

    def test_malformed_status_rejected(self):
        valid = status_fixture()
        for reply in [valid[:-1], valid + b"\0", bytes(64)]:
            with self.assertRaises(ValueError):
                decode(reply)
        for offset in [0, 4, 5, 6, 7, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 63]:
            changed = valid.copy()
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode(changed)

    def test_self_reported_layout_cannot_replace_candidate_binding(self):
        with self.assertRaises(ValueError):
            decode_status(status_fixture(), iram_end=0x40029000, data_start=0x3FFB9000)

    def test_valid_linked_layout(self):
        result = validate_layout(SECTIONS, SYMBOLS)
        self.assertEqual(result["stack_reserved_bytes"], 0x1E000)
        self.assertFalse(result["device_accessed"])

    def test_missing_or_inconsistent_symbols_rejected(self):
        for symbol in SYMBOLS:
            changed = SYMBOLS.copy()
            del changed[symbol]
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                validate_layout(SECTIONS, changed)
        for name, value in [("_data_start", 0x3FFB7000), ("_stack_end", 0x3FFB6000),
                            ("_salpa_pms_iram_end", 0x40050000)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_layout(SECTIONS, {**SYMBOLS, name: value})

    def test_handler_in_flash_is_rejected(self):
        changed = SYMBOLS.copy()
        handler = next(name for name in changed if "memory_fault" in name)
        changed[handler] = 0x40090000
        with self.assertRaises(ValueError):
            validate_layout(SECTIONS, changed)

    def test_code_or_data_crossing_permission_boundary_is_rejected(self):
        for index, address in [(0, 0x40027FFC), (0, 0x40070000), (0, 0x50000000),
                               (2, 0x3FFB7FFC)]:
            changed = copy.deepcopy(SECTIONS)
            changed[index]["address"] = address
            with self.subTest(index=index, address=address), self.assertRaises(ValueError):
                validate_layout(changed, SYMBOLS)
        changed = copy.deepcopy(SECTIONS)
        changed[0]["flags"].discard("READONLY")
        with self.assertRaises(ValueError):
            validate_layout(changed, SYMBOLS)

    def test_objdump_sections_are_parsed_and_empty_input_rejected(self):
        parsed = parse_sections(
            "Idx Name Size VMA LMA File off Algn\n"
            "  0 .rwtext 00001000 40024400 40024400 00002000 2**2\n"
            "                  CONTENTS, ALLOC, LOAD, READONLY, CODE\n"
        )
        self.assertEqual(parsed[0]["address"], 0x40024400)
        self.assertIn("READONLY", parsed[0]["flags"])
        with self.assertRaises(ValueError):
            parse_sections("unrecognized output")

    def test_handler_must_not_call_flash_or_return(self):
        assembly = (
            "40025000 <salpa::platform::memory_protection::hardware::__esp_hal_internal_memory_fault>:\n"
            "40025000: 004136 entry a1, 32\n"
            "40025003: 080c movi.n a8, 0\n"
            "40025005: 61e480 xsr.intenable a8\n"
            "40025008: 002010 rsync\n"
            "4002500b: ffff06 j 4002500b\n"
        )
        validate_handler(assembly, 0x40025000)
        for replacement in ["call8 40090000", "retw.n", "j 40090000"]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                validate_handler(assembly.replace("j 4002500b", replacement), 0x40025000)


if __name__ == "__main__":
    unittest.main()
