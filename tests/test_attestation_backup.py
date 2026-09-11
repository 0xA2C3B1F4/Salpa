from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = load("check_attestation_backup", "check-attestation-backup.py")
GENERATOR = load("attestation_test_certificate", "generate-dev-attestation.py")


class AttestationBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.key = self.directory / "test-key.raw"
        self.cert = self.directory / "test-cert.der"
        self.reference = self.directory / "original-reference.json"
        # Public, deterministic unit-test scalars; never a device identity.
        self.install_test_pair(1)
        self.reference.write_text(json.dumps({"certificate_sha256": hashlib.sha256(self.cert.read_bytes()).hexdigest()}))

    def install_test_pair(self, scalar):
        key = ec.derive_private_key(scalar, ec.SECP256R1())
        self.key.write_bytes(scalar.to_bytes(32, "big"))
        self.key.chmod(0o600)
        self.cert.write_bytes(GENERATOR.build_certificate(key).public_bytes(serialization.Encoding.DER))

    def verify(self):
        return CHECK.verify_backup(self.key, self.cert, self.reference)

    def test_original_pair_passes_without_exporting_material(self):
        result = self.verify()
        self.assertTrue(result["key_and_certificate_match"])
        self.assertFalse(result["device_identity_installed"])
        self.assertTrue(all(isinstance(value, bool) for value in result.values()))

    def test_replacement_pair_cannot_pass_original_reference(self):
        self.install_test_pair(2)
        with self.assertRaisesRegex(CHECK.BackupError, "differs from the original"):
            self.verify()

    def test_wrong_key_is_rejected_even_with_original_certificate(self):
        self.key.write_bytes((2).to_bytes(32, "big"))
        with self.assertRaisesRegex(CHECK.BackupError, "do not match"):
            self.verify()

    def test_missing_key_never_creates_a_replacement(self):
        self.key.unlink()
        with self.assertRaisesRegex(CHECK.BackupError, "missing or unsafe"):
            self.verify()
        self.assertFalse(self.key.exists())

    def test_world_readable_private_key_is_rejected(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(CHECK.BackupError, "owner-only"):
            self.verify()

    def test_symlink_private_key_is_rejected(self):
        original = self.key.with_suffix(".original")
        self.key.rename(original)
        self.key.symlink_to(original)
        with self.assertRaisesRegex(CHECK.BackupError, "missing or unsafe"):
            self.verify()

    def test_fifo_private_key_is_rejected_without_waiting_for_writer(self):
        self.key.unlink()
        os.mkfifo(self.key, 0o600)
        with self.assertRaisesRegex(CHECK.BackupError, "regular file"):
            self.verify()

    def test_missing_original_reference_digest_is_rejected(self):
        self.reference.write_text("{}")
        with self.assertRaisesRegex(CHECK.BackupError, "original reference"):
            self.verify()

    def test_zero_scalar_is_rejected(self):
        self.key.write_bytes(bytes(32))
        with self.assertRaises(CHECK.BackupError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
