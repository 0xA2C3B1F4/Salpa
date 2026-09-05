from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from check_public_history import validate_history
from public_tree import PublicTreeError


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Public test')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.root / 'README.md').write_text('Public fixture\n')
        self.git('add', 'README.md')
        self.git('commit', '--quiet', '-m', 'Public source fixture')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, text=True)

    def test_clean_history(self):
        self.assertEqual(validate_history(self.root), 1)

    def test_private_handoff_cannot_enter_release_history(self):
        (self.root / "implementation_handoff.md").write_text("Internal instructions")
        self.git("add", "implementation_handoff.md")
        self.git("commit", "--quiet", "-m", "Fixture")
        with self.assertRaises(PublicTreeError) as result:
            validate_history(self.root)
        self.assertIn("forbidden historical path", str(result.exception))

    def test_commit_message_is_scanned_without_echoing_match(self):
        synthetic = 'ghp' + '_' + 'A' * 24
        self.git('commit', '--quiet', '--allow-empty', '-m', synthetic)
        with self.assertRaises(PublicTreeError) as result:
            validate_history(self.root)
        self.assertIn('commit metadata', str(result.exception))
        self.assertNotIn(synthetic, str(result.exception))

    def test_annotated_tag_message_is_scanned(self):
        self.git('tag', '-a', 'test', '-m', 'ghp' + '_' + 'B' * 24)
        with self.assertRaises(PublicTreeError) as result:
            validate_history(self.root)
        self.assertIn('tag metadata', str(result.exception))


if __name__ == '__main__':
    unittest.main()
