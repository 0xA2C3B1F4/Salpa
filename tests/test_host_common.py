import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
from host_common import git_output, is_within, parse_sdkconfig, sha256_file


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), TOOLS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGERS = [load(name) for name in (
    "prepare-e000-migration.py", "prepare-signed-ab-package.py", "prepare-protected-package.py"
)]


class HostCommonTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.build = self.root / "build"
        self.build.mkdir()
        self.manifest = self.build / "manifest.json"
        self.artifact = self.build / "app.bin"
        self.artifact.write_bytes(bytes(range(256)) * 8193)
        self.record = {"file": "app.bin", "size": self.artifact.stat().st_size,
                       "sha256": hashlib.sha256(self.artifact.read_bytes()).hexdigest()}

    def test_streaming_digest_preserves_manifest_identity(self):
        self.assertEqual(sha256_file(self.artifact), self.record["sha256"])
        for tool in PACKAGERS:
            self.assertEqual(tool.manifest_artifact(self.manifest, self.record), self.artifact)

    def test_all_packagers_reject_tampered_size_and_digest(self):
        for change in ({"size": 1}, {"sha256": "0" * 64}):
            for tool in PACKAGERS:
                with self.subTest(tool=tool.__name__, change=change):
                    with self.assertRaises(tool.PackageError):
                        tool.manifest_artifact(self.manifest, self.record | change)

    def test_all_packagers_reject_absolute_parent_and_symlink_escapes(self):
        outside = self.root / "outside.bin"
        outside.write_bytes(self.artifact.read_bytes())
        (self.build / "link.bin").symlink_to(outside)
        for value in (str(outside), "../outside.bin", "link.bin"):
            for tool in PACKAGERS:
                with self.subTest(tool=tool.__name__, value=value):
                    with self.assertRaises(tool.PackageError):
                        tool.manifest_artifact(self.manifest, self.record | {"file": value})

    def test_manifest_kind_and_schema_checks_remain_with_each_packager(self):
        for value in ([], {"schema": 2, "kind": "expected"}, {"schema": 1, "kind": "wrong"}):
            self.manifest.write_text(json.dumps(value))
            for tool in PACKAGERS:
                with self.assertRaises(tool.PackageError):
                    tool.load_manifest(self.manifest, "expected")

    def test_containment_uses_path_components_and_resolved_aliases(self):
        self.assertTrue(is_within(self.artifact.resolve(), self.build.resolve()))
        self.assertFalse(is_within(self.root / "build-other" / "app.bin", self.build))
        self.assertFalse(is_within((self.build / ".." / "outside").resolve(), self.build))

    def test_sdkconfig_preserves_disabled_and_quoted_values(self):
        path = self.root / "sdkconfig"
        path.write_text('CONFIG_TARGET="esp32s2"\n# CONFIG_UNSAFE is not set\nCONFIG_TEXT="a=b"\n# comment\n')
        self.assertEqual(parse_sdkconfig(path), {
            "CONFIG_TARGET": '"esp32s2"', "CONFIG_UNSAFE": "n", "CONFIG_TEXT": '"a=b"'
        })

    def test_git_errors_propagate_from_the_requested_directory(self):
        with self.assertRaises(subprocess.CalledProcessError):
            git_output(self.root, "rev-parse", "--verify", "HEAD")


if __name__ == "__main__":
    unittest.main()
