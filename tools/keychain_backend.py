"""macOS helper transport. Only firmware, public keys and signatures cross IPC."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile

DEFAULT_HELPER = Path.home() / "Library/Application Support/RissoKey/rissokey-key-helper"


def check_helper(helper: Path) -> None:
    info = helper.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("Key helper must be an owner-only regular executable")
    subprocess.run(
        ["codesign", "--verify", "--strict", str(helper)], check=True, capture_output=True
    )


class KeychainSigningKey:
    def __init__(self, helper: Path, public_key: Path):
        self.helper = helper.expanduser().absolute()
        self.public_key = public_key
        check_helper(self.helper)

    def sign_image(self, python: Path, source: Path, output: Path) -> None:
        if output.exists() or output.is_symlink():
            raise RuntimeError("Signed output already exists")
        # Freeze bytes before asking for approval. No private-key temporary files.
        data = source.read_bytes()
        if not data or len(data) > 16 * 1024 * 1024:
            raise RuntimeError("Invalid signing input length")
        data += b"\xff" * (-len(data) % 4096)
        with tempfile.TemporaryDirectory(prefix="salpa-sign-") as folder:
            padded = Path(folder) / "image-padded.bin"
            signature = Path(folder) / "signature.bin"
            padded.write_bytes(data)
            subprocess.run([str(self.helper), "sign", str(padded), str(signature)], check=True)
            if signature.stat().st_size != 384:
                raise RuntimeError("Helper returned an invalid RSA-3072 signature")
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "espsecure",
                    "sign-data",
                    "--version",
                    "2",
                    "--pub-key",
                    str(self.public_key),
                    "--signature",
                    str(signature),
                    "--output",
                    str(output),
                    str(padded),
                ],
                check=True,
            )


class KeychainFlashKey:
    def __init__(self, helper: Path):
        self.helper = helper.expanduser().absolute()
        check_helper(self.helper)

    def encrypt(self, plaintext: Path, ciphertext: Path, address: int) -> None:
        subprocess.run(
            [str(self.helper), "encrypt", hex(address), str(plaintext), str(ciphertext)],
            check=True,
        )
        if ciphertext.stat().st_size != plaintext.stat().st_size:
            raise RuntimeError("Flash encryption changed image length")
