#!/usr/bin/env python3
"""Build and install the local helper. Never imports keys or changes firmware."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--identity', required=True, help='Existing macOS code-signing certificate SHA-1; not a firmware key')
args = parser.parse_args()
source = Path(__file__).resolve().parent / 'main.swift'
destination = Path.home() / 'Library/Application Support/RissoKey'
destination.mkdir(mode=0o700, parents=True, exist_ok=True)
mode = destination.lstat()
if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or mode.st_mode & 0o077:
    raise SystemExit('Install directory must be owner-only and must not be a symlink')
with tempfile.TemporaryDirectory(prefix='rissokey-key-helper-build-') as temp:
    folder = Path(temp)
    binary = folder / 'rissokey-key-helper'
    subprocess.run(['swiftc', '-O', '-suppress-warnings', '-module-cache-path', str(folder / 'module-cache'), str(source), '-o', str(binary)], check=True)
    subprocess.run(['codesign', '--force', '--sign', args.identity, '--options', 'runtime', '--identifier', 'fi.rissotek.rissokey.keyhelper', str(binary)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True)
    staged = destination / '.rissokey-key-helper.new'
    if staged.exists() or staged.is_symlink():
        raise SystemExit('Staging path already exists; inspect it first')
    shutil.copyfile(binary, staged)
    staged.chmod(0o700)
    staged.replace(destination / 'rissokey-key-helper')
print('Installed signed helper:', destination / 'rissokey-key-helper')
