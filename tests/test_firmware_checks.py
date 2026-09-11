import importlib.util
import json
import os
import subprocess
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
        runtimes = {(p[0], p[1]) for p in CHECKS.PROFILES.values() if p[2] == "salpa"}
        self.assertEqual(runtimes, {("esp32s2", "legacy-0x8000"),
                                    ("esp32s2", "signed-ab-encrypted"),
                                    ("esp32s3", "legacy-0x8000")})

    def test_fixture_build_does_not_inherit_device_inputs_or_other_mode_approvals(self):
        inherited = {"PATH": "toolchain", "SALPA_DEV_ATTESTATION_KEY": "not-a-fixture",
                     "SALPA_PROVISIONING_ACK": "ERASE_FIDO_STORE",
                     "SALPA_ATTESTATION_IMPORT_ACK": "INSTALL_ATTESTATION",
                     "SALPA_PHYSICAL_FAULT_TEST_ACK": "INTERRUPT_FIDO_STORE",
                     "ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION": "65535"}
        inherited.update({key.replace("SALPA_", "RISSO_KEY_"): "legacy-private-fixture"
                          for key in list(inherited) if key.startswith("SALPA_")})
        with tempfile.TemporaryDirectory() as folder:
            for profile in CHECKS.PROFILES.values():
                env = CHECKS.fixture_environment(Path(folder), profile, inherited)
                self.assertEqual(env["PATH"], "toolchain")
                self.assertNotIn("not-a-fixture", env.values())
                self.assertNotIn("legacy-private-fixture", env.values())
                self.assertFalse(any(key.startswith("RISSO_KEY_") for key in env))
                self.assertEqual(env["ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION"], "3")
                self.assertEqual("SALPA_PROVISIONING_ACK" in env,
                                 profile[2] in ("provision-storage", "provision-development"))
                self.assertEqual("SALPA_ATTESTATION_IMPORT_ACK" in env,
                                 profile[2] == "import-attestation")
                self.assertEqual("SALPA_PHYSICAL_FAULT_TEST_ACK" in env,
                                 profile[2] == "storage-powercut-test")
                self.assertEqual("SALPA_EPOCH_PREVIEW_ACK" in env,
                                 "security-epoch-preview" in profile[3])
                self.assertEqual("SALPA_EPOCH_PLAN_PATH" in env,
                                 "security-epoch-maintenance" in profile[3])


    def test_development_fixture_is_not_an_attestation_certificate(self):
        with tempfile.TemporaryDirectory() as folder:
            env = CHECKS.fixture_environment(Path(folder), CHECKS.PROFILES["s2-development-provision"], {})
            scalar = Path(env["SALPA_DEV_ATTESTATION_KEY"]).read_bytes()
            certificate = Path(env["SALPA_DEV_ATTESTATION_CERT"]).read_bytes()
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


class CargoWrapperAliasTests(unittest.TestCase):
    def test_target_selection_accepts_both_names_and_preserves_empty_default(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "include").mkdir()
            (root / "include/stdint.h").touch()
            compiler = "#!/bin/sh\ncase \"$1\" in\n-print-file-name=include) printf '%s\\n' \"$ALIAS_TEST_INCLUDE\";;\n-print-sysroot) printf '%s\\n' \"$ALIAS_TEST_SYSROOT\";;\nesac\n"
            for name in ("xtensa-esp32s2-elf-gcc", "xtensa-esp32s3-elf-gcc"):
                path = root / name
                path.write_text(compiler)
                path.chmod(0o755)
            for name in ("xtensa-esp32s2-elf-ar", "xtensa-esp32s3-elf-ar", "cargo"):
                path = root / name
                path.write_text("#!/bin/sh\nprintf '%s\\n' \"$CARGO_BUILD_TARGET\"\n")
                path.chmod(0o755)
            base = {key: value for key, value in os.environ.items()
                    if not key.startswith(("SALPA_", "RISSO_KEY_"))}
            base.update(PATH=str(root), LIBCLANG_PATH=str(root), TMPDIR=str(root),
                        ALIAS_TEST_INCLUDE=str(root / "include"), ALIAS_TEST_SYSROOT=str(root))
            for inputs, target in (({"SALPA_MCU": "esp32s2"}, "esp32s2"),
                                   ({"RISSO_KEY_MCU": "esp32s2"}, "esp32s2"),
                                   ({"SALPA_MCU": "esp32s2", "RISSO_KEY_MCU": "esp32s2"}, "esp32s2"),
                                   ({}, "esp32s3"), ({"RISSO_KEY_MCU": ""}, "esp32s3")):
                with self.subTest(inputs=inputs):
                    result = subprocess.run([str(ROOT / "tools/cargo-esp"), "check"],
                                            env=base | inputs, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), f"xtensa-{target}-none-elf")
            result = subprocess.run([str(ROOT / "tools/cargo-esp"), "check"],
                                    env=base | {"SALPA_MCU": "esp32s2", "RISSO_KEY_MCU": "esp32s3"},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("conflicting environment variables", result.stderr)
            self.assertNotIn("esp32s2", result.stderr)
            self.assertNotIn("esp32s3", result.stderr)
