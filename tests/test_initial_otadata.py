import importlib.util
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("initial_otadata", TOOLS / "prepare-initial-otadata.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InitialOtaDataTests(unittest.TestCase):
    def test_seed_matches_pinned_idf_entry_and_preserves_erased_second_entry(self):
        data = module.initial_metadata(b"\xff" * 8192)
        expected = bytes.fromhex("01000000") + b"\xff" * 20 + bytes.fromhex(
            "020000009a984347"
        )
        self.assertEqual(data, expected + b"\xff" * (8192 - 32))
        sequence, = struct.unpack_from("<I", data)
        self.assertEqual((sequence - 1) % 2, 0)

    def test_refuses_existing_history_in_either_sector(self):
        for offset in (0, 31, 4095, 4096, 8191):
            raw = bytearray(b"\xff" * 8192)
            raw[offset] = 0
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                module.initial_metadata(bytes(raw))

    def test_refuses_short_long_or_encrypted_readbacks(self):
        for data in (b"", b"\xff" * 4096, b"\xff" * 8193, b"\x93" * 8192):
            with self.assertRaises(ValueError):
                module.initial_metadata(data)


if __name__ == "__main__":
    unittest.main()
