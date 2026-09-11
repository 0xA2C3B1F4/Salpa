#!/usr/bin/env python3
"""Prepare encrypted initial OTA metadata for a verified, fresh ota_0 device.

This host-only operation does not flash a device. The installer must recheck
device identity, the known-good ota_0 image and erased raw metadata immediately
before writing. Never use this seed to repair or replace existing OTA history.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

from keychain_backend import DEFAULT_HELPER, KeychainFlashKey

OTADATA_OFFSET = 0xF000
OTADATA_SIZE = 8192


def initial_metadata(erased_readback: bytes) -> bytes:
    if erased_readback != b"\xff" * OTADATA_SIZE:
        raise ValueError("initialization requires exactly 8192 raw erased bytes")
    # esp_rom_crc32_le(UINT32_MAX, sequence, 4), pinned ESP-IDF sequence-1 vector.
    crc = 0
    for byte in struct.pack("<I", 1):
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    data = bytearray(erased_readback)
    struct.pack_into("<I", data, 0, 1)
    struct.pack_into("<II", data, 24, 2, crc ^ 0xFFFFFFFF)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--erased-otadata-readback", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--key-helper", type=Path, default=DEFAULT_HELPER)
    args = parser.parse_args()
    os.umask(0o077)
    source = args.erased_otadata_readback
    if source.is_symlink() or not source.is_file():
        raise SystemExit("readback must be a regular file")
    plaintext = initial_metadata(source.read_bytes())
    output = args.output_dir.expanduser().resolve()
    root = Path(__file__).resolve().parent.parent
    if output.is_relative_to(root):
        raise SystemExit("keep device-specific ciphertext outside the repository")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    plain_path = output / ".otadata-public-plaintext.bin"
    cipher_path = output / "initial-otadata-encrypted.bin"
    try:
        plain_path.write_bytes(plaintext)
        KeychainFlashKey(args.key_helper).encrypt(plain_path, cipher_path, OTADATA_OFFSET)
    finally:
        plain_path.unlink(missing_ok=True)
    cipher = cipher_path.read_bytes()
    manifest = {
        "schema": 1,
        "kind": "rissokey-initial-encrypted-otadata",
        "offset": OTADATA_OFFSET,
        "size": len(cipher),
        "sha256": hashlib.sha256(cipher).hexdigest(),
        "active_slot": 0,
        "sequence": 1,
        "state": "VALID",
        "second_entry_plaintext_erased": True,
        "keychain_encryption_and_in_memory_roundtrip": True,
        "preconditions": [
            "Identify the authorized device again before writing",
            "Both raw otadata sectors must still be completely erased",
            "Verify the installed ota_0 ciphertext against its trusted package",
            "Complete FIDO and credential power-cycle acceptance on that ota_0",
            "Preserve encrypted credential storage and all existing keys",
        ],
        "flash_performed": False,
        "efuse_operations_performed": False,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Prepared initial encrypted OTA metadata; no device accessed or key exported.")


if __name__ == "__main__":
    main()
