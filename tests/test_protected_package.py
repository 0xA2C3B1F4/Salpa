from __future__ import annotations

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
    def test_rollback_fixture_keeps_protected_runtime_contract(self) -> None:
        normal = set(BUILD.selected_features("runtime", "normal"))
        failure = set(BUILD.selected_features("runtime", "rollback-failure"))
        self.assertEqual(failure - normal, {"signed-ab-failure-test"})
        self.assertIn("release-flash-encryption", failure)
        self.assertIn("usb-signed-update", failure)

    def test_runtime_variant_cannot_select_provisioner(self) -> None:
        with self.assertRaisesRegex(BUILD.BuildError, "only valid"):
            BUILD.selected_features("storage-provisioner", "rollback-failure")

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
