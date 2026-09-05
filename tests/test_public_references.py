from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from source_references import missing_references


class PublicReferenceTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.paths = []
        self.add("Cargo.toml", '[[bin]]\nname = "example"\npath = "src/bin/main.rs"\n')
        self.add("src/bin/main.rs", "fn main() {}\n")

    def add(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.paths.append(PurePosixPath(name))

    def check(self):
        return missing_references(self.root, self.paths)

    def test_declared_binary_cannot_be_omitted_from_export(self):
        self.paths.remove(PurePosixPath("src/bin/main.rs"))
        self.assertIn("src/bin/main.rs", self.check()[0])

    def test_test_only_module_cannot_be_omitted(self):
        self.add("src/lib.rs", "#[cfg(test)]\npub mod validation;\n")
        self.add("src/validation.rs", "pub fn validate() {}\n")
        self.assertEqual(self.check(), [])
        self.paths.remove(PurePosixPath("src/validation.rs"))
        self.assertIn("src/validation.rs", self.check()[0])

    def test_module_directory_and_explicit_source_paths(self):
        self.add("src/lib.rs", 'mod platform;\n#[path = "shared.rs"]\nmod contract;\n')
        self.add("src/platform/mod.rs", "pub mod storage;\nmod inline { fn example() {} }\n")
        self.add("src/platform/storage.rs", "pub struct Store;\n")
        self.add("src/shared.rs", "pub const VERSION: u8 = 1;\n")
        self.assertEqual(self.check(), [])

    def test_relative_document_links_require_selected_files(self):
        self.add("README.md", "[Guide](docs/guide.md#build)\n[External](https://example.com/)\n")
        self.add("docs/guide.md", "# Build\n[Home](../README.md)\n")
        self.assertEqual(self.check(), [])
        self.paths.remove(PurePosixPath("docs/guide.md"))
        self.assertIn("docs/guide.md", self.check()[0])

    def test_link_to_unselected_file_outside_root_is_rejected(self):
        self.add("README.md", "[Outside](../not-public.md)\n")
        self.assertEqual(len(self.check()), 1)

    def test_absolute_reference_is_reported_without_external_path(self):
        self.add("README.md", "[Outside](/outside-export/example.md)\n")
        self.assertEqual(self.check(), ["README.md: missing public reference outside export"])

    def test_fenced_link_example_is_not_a_document_reference(self):
        self.add("README.md", "```markdown\n[Example](not-a-real-link.md)\n```\n")
        self.assertEqual(self.check(), [])


if __name__ == "__main__":
    unittest.main()
