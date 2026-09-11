from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    'keychain_test_backend', ROOT / 'tools/keychain_backend.py'
)
BACKEND = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BACKEND)


class KeychainBackendTests(unittest.TestCase):
    def make_signer(self):
        with patch.object(BACKEND, 'check_helper'):
            return BACKEND.KeychainSigningKey(Path('/signed/helper'), Path('/public.pem'))

    def test_cancel_stops_before_packaging(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'image.bin'
            source.write_bytes(b'image')
            with patch.object(
                BACKEND.subprocess,
                'run',
                side_effect=subprocess.CalledProcessError(1, ['helper']),
            ) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    self.make_signer().sign_image(Path('/python'), source, Path(folder) / 'out.bin')
                self.assertEqual(run.call_count, 1)
                self.assertFalse((Path(folder) / 'out.bin').exists())

    def test_padding_and_external_signature_only(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'image.bin'
            source.write_bytes(b'image')
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[1] == 'sign':
                    self.assertEqual(Path(argv[2]).read_bytes(), b'image' + b'\xff' * 4091)
                    Path(argv[3]).write_bytes(b'x' * 384)

            with patch.object(BACKEND.subprocess, 'run', side_effect=run):
                self.make_signer().sign_image(Path('/python'), source, Path(folder) / 'out.bin')
            self.assertEqual(len(calls), 2)
            self.assertIn('--pub-key', calls[1])
            self.assertIn('--signature', calls[1])
            self.assertNotIn('--keyfile', calls[1])
            self.assertFalse(Path(calls[0][2]).exists())

    def test_malformed_signature_stops_before_packaging(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'image.bin'
            source.write_bytes(b'image')

            def run(argv, **kwargs):
                Path(argv[3]).write_bytes(b'wrong-size')

            with patch.object(BACKEND.subprocess, 'run', side_effect=run) as calls:
                with self.assertRaisesRegex(RuntimeError, 'signature'):
                    self.make_signer().sign_image(Path('/python'), source, Path(folder) / 'out.bin')
                self.assertEqual(calls.call_count, 1)

    def test_refuses_overwrite_before_authentication(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'image.bin'
            source.write_bytes(b'image')
            with patch.object(BACKEND.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'exists'):
                    self.make_signer().sign_image(Path('/python'), source, source)
                run.assert_not_called()

    def test_refuses_world_accessible_or_symlink_helper(self):
        with tempfile.TemporaryDirectory() as folder:
            helper = Path(folder) / 'helper'
            helper.write_bytes(b'not executable')
            helper.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, 'owner-only'):
                BACKEND.check_helper(helper)
            helper.chmod(0o700)
            link = Path(folder) / 'link'
            link.symlink_to(helper)
            with self.assertRaisesRegex(RuntimeError, 'owner-only'):
                BACKEND.check_helper(link)


if __name__ == '__main__':
    unittest.main()
