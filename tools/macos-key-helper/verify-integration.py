#!/usr/bin/env python3
"""Interactive host-only verification against an existing trusted package."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from keychain_backend import DEFAULT_HELPER, KeychainSigningKey, KeychainFlashKey
from cryptography.hazmat.primitives import serialization

parser = argparse.ArgumentParser()
parser.add_argument('--helper', type=Path, default=DEFAULT_HELPER)
parser.add_argument('--public-key', type=Path, required=True)
parser.add_argument('--existing-signed-image', type=Path, required=True)
parser.add_argument('--flash-plaintext', type=Path, required=True)
parser.add_argument('--existing-ciphertext', type=Path, required=True)
parser.add_argument('--flash-address', type=lambda value: int(value, 0), required=True)
parser.add_argument('--output-dir', type=Path, required=True)
args = parser.parse_args()

# Authenticate the input before removing its existing signature sector.
subprocess.run(
    [
        sys.executable,
        '-m',
        'espsecure',
        'verify-signature',
        '--version',
        '2',
        '--keyfile',
        str(args.public_key),
        str(args.existing_signed_image),
    ],
    check=True,
    capture_output=True,
)
public = serialization.load_pem_public_key(args.public_key.read_bytes())
fingerprint = hashlib.sha256(
    public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
).hexdigest()
inventory = Path.home() / 'Library/Application Support/RissoKey/key-inventory.json'
if (
    json.loads(inventory.read_text())['keys']['signing']['public_key_pkcs1_sha256']
    != fingerprint
):
    raise SystemExit('Inventory signing root differs from the trusted public key')

args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
unsigned = args.output_dir / 'existing-image-padded.bin'
unsigned.write_bytes(args.existing_signed_image.read_bytes()[:-4096])
signed = args.output_dir / 'keychain-signed.bin'
KeychainSigningKey(args.helper, args.public_key).sign_image(
    Path(sys.executable), unsigned, signed
)
subprocess.run(
    [
        sys.executable,
        '-m',
        'espsecure',
        'verify-signature',
        '--version',
        '2',
        '--keyfile',
        str(args.public_key),
        str(signed),
    ],
    check=True,
    capture_output=True,
)

cipher = args.output_dir / 'keychain-encrypted.bin'
KeychainFlashKey(args.helper).encrypt(args.flash_plaintext, cipher, args.flash_address)
if cipher.read_bytes() != args.existing_ciphertext.read_bytes():
    raise SystemExit(
        'Ciphertext differs; check that the plaintext is the exact packaged artifact'
    )

result = {
    'schema': 1,
    'verified_at': datetime.now(timezone.utc).isoformat(),
    'existing_public_root_matched': True,
    'keychain_rsa_signature_verified_by_espsecure': True,
    'flash_ciphertext_matched_current_package': True,
    'hardware_operations_performed': False,
}
(args.output_dir / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(
    'PASS: Keychain signature matches the existing trust root; '
    'ciphertext matches the existing package'
)
