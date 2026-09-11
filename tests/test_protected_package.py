from __future__ import annotations

import ast
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
    def test_flash_encryption_manifest_matches_the_helper_key_contract(self):
        # Execute the actual manifest expression without signing/encrypting images
        # or invoking Keychain. Undefined names must fail this test.
        tree = ast.parse((ROOT / "tools" / "prepare-protected-package.py").read_text())
        package = next(node.value for node in ast.walk(tree)
                       if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "package"
                               for target in node.targets))
        expression = next(value for key, value in zip(package.keys, package.values)
                          if isinstance(key, ast.Constant) and key.value == "flash_encryption")
        contract = eval(compile(ast.Expression(expression), "package manifest", "eval"), vars(PACKAGE))
        self.assertEqual(contract["algorithm"], "AES-128-XTS")
        self.assertEqual(contract["key_bytes"], 32)
        self.assertFalse(contract["key_included"])
        self.assertTrue(contract["exact_destination_offset_required"])

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
