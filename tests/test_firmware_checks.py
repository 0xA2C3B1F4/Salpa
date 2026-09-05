import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from cryptography import x509

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("firmware_checks", ROOT / "tools/check-firmware-builds.py")
CHECKS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECKS)


class FirmwareCheckTests(unittest.TestCase):
    def test_matrix_covers_every_declared_binary_and_runtime_target(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual({p[2] for p in CHECKS.PROFILES.values()},
                         {b["name"] for b in manifest["bin"]})
        runtimes = {(p[0], p[1]) for p in CHECKS.PROFILES.values() if p[2] == "rissokey"}
        self.assertEqual(runtimes, {("esp32s2", "legacy-0x8000"),
                                    ("esp32s2", "signed-ab-encrypted"),
                                    ("esp32s3", "legacy-0x8000")})

    def test_fixture_build_does_not_inherit_device_inputs_or_other_mode_approvals(self):
        inherited = {"PATH": "toolchain", "RISSO_KEY_DEV_ATTESTATION_KEY": "not-a-fixture",
                     "RISSO_KEY_PROVISIONING_ACK": "ERASE_FIDO_STORE",
                     "RISSO_KEY_ATTESTATION_IMPORT_ACK": "INSTALL_ATTESTATION",
                     "RISSO_KEY_PHYSICAL_FAULT_TEST_ACK": "INTERRUPT_FIDO_STORE",
                     "ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION": "65535"}
        with tempfile.TemporaryDirectory() as folder:
            for profile in CHECKS.PROFILES.values():
                env = CHECKS.fixture_environment(Path(folder), profile, inherited)
                self.assertEqual(env["PATH"], "toolchain")
                self.assertNotIn("not-a-fixture", env.values())
                self.assertEqual(env["ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION"], "3")
                self.assertEqual("RISSO_KEY_PROVISIONING_ACK" in env,
                                 profile[2] in ("provision-storage", "provision-development"))
                self.assertEqual("RISSO_KEY_ATTESTATION_IMPORT_ACK" in env,
                                 profile[2] == "import-attestation")
                self.assertEqual("RISSO_KEY_PHYSICAL_FAULT_TEST_ACK" in env,
                                 profile[2] == "storage-powercut-test")

    def test_development_fixture_is_not_an_attestation_certificate(self):
        with tempfile.TemporaryDirectory() as folder:
            env = CHECKS.fixture_environment(Path(folder), CHECKS.PROFILES["s2-development-provision"], {})
            scalar = Path(env["RISSO_KEY_DEV_ATTESTATION_KEY"]).read_bytes()
            certificate = Path(env["RISSO_KEY_DEV_ATTESTATION_CERT"]).read_bytes()
            self.assertEqual(int.from_bytes(scalar, "big"), 1)
            with self.assertRaises(ValueError):
                x509.load_der_x509_certificate(certificate)
            # Keep the early AAGUID assertion satisfiable so the link check
            # includes the provisioning path rather than only a panic loop.
            source = (ROOT / "src/identity.rs").read_text()
            body = source.split("pub const DEVELOPMENT_AAGUID:", 1)[1].split("= [", 1)[1].split("];", 1)[0]
            aaguid = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", body))
            self.assertTrue(certificate.endswith(aaguid))

    def test_clippy_only_invocation_denies_warnings_and_records_no_link_result(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "checks"
            argv = ["check-firmware-builds.py", "--profile", "s3-bringup",
                    "--check", "clippy", "--build-dir", str(output)]
            with patch.object(sys, "argv", argv), patch.object(CHECKS.subprocess, "run") as run:
                run.return_value.returncode = 0
                CHECKS.main()
            command = run.call_args.args[0]
            self.assertEqual(command[:2], ["./tools/cargo-esp", "clippy"])
            self.assertEqual(command[-3:], ["--", "-D", "warnings"])
            record = json.loads((output / "build-results.json").read_text())
            self.assertEqual(record["results"][0]["check"], "clippy")
            self.assertNotIn("elf_sha256", record["results"][0])


if __name__ == "__main__":
    unittest.main()
