from __future__ import annotations

import copy
import json
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load_tool(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BUILD = load_tool("rissokey_build_protected_app", "build-protected-app.py")
PACKAGE = load_tool("rissokey_prepare_protected_package", "prepare-protected-package.py")


class ProtectedPackageTests(unittest.TestCase):
    def test_complete_manifest_matches_pre_refactor_format(self):
        # Captured from f23bf0a's manifest expression using public synthetic inputs.
        expected = json.loads((ROOT / "tests/fixtures/protected-package-manifest.json").read_text())
        actual = PACKAGE.build_package_manifest(
            files=copy.deepcopy(expected["files"]), writes={},
            runtime_usb_name="runtime-usb-signed.bin",
            rollback_failure_usb_name="rollback-failure-usb-signed.bin",
            rollback_secure_version=5, source_commit="commit-fixture",
            source_tree="tree-fixture", partition_hash="partition-fixture",
            plan_hash="plan-fixture", digest="root-fixture",
            created_at="2026-09-17T00:00:00+00:00",
        )
        self.assertEqual(actual, expected)

    def test_bootloader_contract_rejects_each_invalid_field(self):
        valid = {
            "source_commit": "commit", "source_tree": "tree", "build_only": True,
            "efuse_operations_performed": False,
            "security_profile": "wemos-s2-mini-protected-prototype",
            "protection": {"external_efuse_plan_required": True,
                           "flash_encryption": "release", "secure_boot": "v2-rsa3072"},
            "custom_boot_verification": {},
        }
        PACKAGE.validate_bootloader_manifest(valid, "commit", "tree")
        mutations = [(key, None) for key in valid]
        mutations += [("build_only", 1), ("efuse_operations_performed", 0)]
        for key, value in mutations:
            with self.subTest(field=key, value=value), self.assertRaises(PACKAGE.PackageError):
                PACKAGE.validate_bootloader_manifest(valid | {key: value}, "commit", "tree")
        for key in valid["protection"]:
            changed = copy.deepcopy(valid)
            changed["protection"][key] = None
            with self.subTest(protection=key), self.assertRaises(PACKAGE.PackageError):
                PACKAGE.validate_bootloader_manifest(changed, "commit", "tree")

    def test_application_contract_rejects_role_provenance_and_feature_changes(self):
        for image, contract in PACKAGE.APPLICATION_CONTRACTS.items():
            valid = {key: contract[key] for key in ("image", "image_version", "runtime_variant")}
            valid.update(
                secure_version=5, build_only=True, efuse_operations_performed=False,
                source={"commit": "commit", "tree": "tree",
                        "partition_table_sha256": "partition", "efuse_plan_sha256": "plan"},
                build={"partition_profile": "signed-ab-encrypted",
                       "security_profile": "wemos-s2-mini-protected-prototype",
                       "features": sorted(contract["features"])},
            )
            def validate(value):
                PACKAGE.validate_application_manifest(value, image, "commit", "tree", "partition", "plan")
            validate(valid)
            for epoch in (0, 16):
                validate(valid | {"secure_version": epoch})
            mutations = [(key, "wrong") for key in valid]
            mutations += [("secure_version", value) for value in (None, True, -1, 17)]
            mutations += [("build_only", 1), ("efuse_operations_performed", 0)]
            for key, value in mutations:
                with self.subTest(image=image, field=key, value=value), self.assertRaises(PACKAGE.PackageError):
                    validate(valid | {key: value})
            for section in ("source", "build"):
                for key in valid[section]:
                    changed = copy.deepcopy(valid)
                    changed[section][key] = [] if key == "features" else "wrong"
                    with self.subTest(image=image, section=section, field=key), self.assertRaises(PACKAGE.PackageError):
                        validate(changed)
            changed = copy.deepcopy(valid)
            changed["build"]["features"].append("firmware-diagnostics")
            with self.subTest(image=image, extra_feature=True), self.assertRaises(PACKAGE.PackageError):
                validate(changed)

    def test_trust_roots_and_rollback_epoch_are_bound_before_signing(self):
        verification = {"public_key_digest": "root"}
        applications = {
            "runtime": {"trusted_public_key_digest": "root", "secure_version": 5},
            "rollback-failure": {"trusted_public_key_digest": "root", "secure_version": 5},
            "storage-provisioner": {"trusted_public_key_digest": None},
        }
        PACKAGE.validate_trust_roots(verification, applications, "root")
        with self.assertRaisesRegex(PACKAGE.PackageError, "bootloader trust root"):
            PACKAGE.validate_trust_roots({}, applications, "root")
        for image in applications:
            changed = copy.deepcopy(applications)
            changed[image]["trusted_public_key_digest"] = "wrong"
            with self.subTest(image=image), self.assertRaises(PACKAGE.PackageError):
                PACKAGE.validate_trust_roots(verification, changed, "root")
        changed = copy.deepcopy(applications)
        changed["rollback-failure"]["secure_version"] = 4
        with self.assertRaisesRegex(PACKAGE.PackageError, "same secure version"):
            PACKAGE.validate_trust_roots(verification, changed, "root")

    def test_runtime_epochs_must_fit_the_hardware_bit_count(self) -> None:
        for value in range(17):
            BUILD.validate_secure_version("runtime", value)
        for value in (None, -1, 17, 65535, 0xFFFF_FFFF, True):
            with self.subTest(value=value), self.assertRaises(BUILD.BuildError):
                BUILD.validate_secure_version("runtime", value)
        BUILD.validate_secure_version("storage-provisioner", None)
        with self.assertRaises(BUILD.BuildError):
            BUILD.validate_secure_version("storage-provisioner", 3)

    def test_rollback_fixture_keeps_protected_runtime_contract(self) -> None:
        normal = set(BUILD.selected_features("runtime", "normal"))
        failure = set(BUILD.selected_features("runtime", "rollback-failure"))
        self.assertEqual(failure - normal, {"signed-ab-failure-test"})
        self.assertIn("release-flash-encryption", failure)
        self.assertIn("usb-signed-update", failure)

    def test_epoch_preview_is_separate_from_normal_and_other_diagnostics(self):
        normal = set(BUILD.selected_features("runtime", "normal"))
        preview = set(BUILD.selected_features("runtime", "epoch-preview"))
        self.assertEqual(preview - normal, {"security-epoch-preview"})
        self.assertNotIn("security-epoch-preview", normal)
        self.assertNotIn("signed-ab-failure-test", preview)

    def test_runtime_variant_cannot_select_provisioner(self) -> None:
        with self.assertRaisesRegex(BUILD.BuildError, "only valid"):
            BUILD.selected_features("storage-provisioner", "rollback-failure")

    def test_counter_maintenance_is_never_selected_by_a_normal_build(self):
        normal = set(BUILD.selected_features("runtime", "normal"))
        maintenance = set(BUILD.selected_features("runtime", "epoch-maintenance"))
        self.assertEqual(maintenance - normal, {"security-epoch-maintenance"})
        self.assertNotIn("security-epoch-maintenance", normal)
        self.assertNotIn("security-epoch-preview", maintenance)

    def test_package_requires_distinct_normal_and_failure_contracts(self) -> None:
        contracts = PACKAGE.APPLICATION_CONTRACTS
        self.assertEqual(
            set(contracts), {"runtime", "rollback-failure", "storage-provisioner"}
        )
        self.assertEqual(contracts["runtime"]["runtime_variant"], "normal")
        self.assertEqual(
            contracts["rollback-failure"]["runtime_variant"], "rollback-failure"
        )
        self.assertEqual(
            contracts["rollback-failure"]["image_version"], "0.1.1-ab-fail"
        )
        self.assertNotIn(
            "signed-ab-failure-test", contracts["runtime"]["features"]
        )
        self.assertIn(
            "signed-ab-failure-test", contracts["rollback-failure"]["features"]
        )


if __name__ == "__main__":
    unittest.main()
