#!/usr/bin/env python3
"""Verify an existing development-attestation backup against its original reference."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import stat
import sys
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

sys.dont_write_bytecode = True
AAGUID = bytes.fromhex("989e2cc205df4e64806822683886e8b3")
AAGUID_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


class BackupError(RuntimeError):
    """The supplied files do not prove recoverability of the original identity."""


def read_regular(path: Path, limit: int, *, secret: bool = False) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise BackupError("a required backup/reference file is missing or unsafe") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise BackupError("backup/reference must be a bounded regular file")
        if secret and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise BackupError("attestation key must belong to the current user and be owner-only")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise BackupError("backup/reference file exceeded its size limit")
        return data
    except OSError as error:
        raise BackupError("backup/reference file could not be read safely") from error
    finally:
        os.close(descriptor)


def verify_backup(key_path: Path, certificate_path: Path, reference_path: Path) -> dict[str, bool]:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        reference = json.loads(read_regular(reference_path, 64 * 1024))
        expected = reference.get("certificate_sha256")
        if not isinstance(expected, str) or len(expected) != 64 or any(
            value not in "0123456789abcdef" for value in expected
        ):
            raise BackupError("original reference must contain a certificate SHA-256 digest")
        certificate_data = read_regular(certificate_path, 16 * 1024)
        if hashlib.sha256(certificate_data).hexdigest() != expected:
            raise BackupError("certificate differs from the original reference")
        key_data = read_regular(key_path, 32, secret=True)
        if len(key_data) != 32:
            raise BackupError("expected the original 32-byte raw P-256 key")
        private_key = ec.derive_private_key(int.from_bytes(key_data, "big"), ec.SECP256R1())
        certificate = x509.load_der_x509_certificate(certificate_data)
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise BackupError("attestation certificate must contain a P-256 public key")
        if public_key.public_numbers() != private_key.public_key().public_numbers():
            raise BackupError("attestation key and certificate do not match")
        extension = certificate.extensions.get_extension_for_oid(AAGUID_OID)
        if not isinstance(extension.value, x509.UnrecognizedExtension) or (
            extension.value.value != b"\x04\x10" + AAGUID
        ):
            raise BackupError("attestation certificate has an unexpected AAGUID")
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    except BackupError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, InvalidSignature, x509.ExtensionNotFound) as error:
        raise BackupError("attestation backup/reference validation failed") from error
    return {
        "original_certificate_reference_matches": True,
        "key_and_certificate_match": True,
        "development_aaguid_matches": True,
        "certificate_self_signature_verified": True,
        "private_key_owner_only": True,
        "device_identity_installed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path,
                        help="original manifest/provenance record from before the loss or erase")
    args = parser.parse_args()
    try:
        verify_backup(args.key, args.certificate, args.reference)
    except BackupError as error:
        print(f"attestation backup not verified: {error}", file=sys.stderr)
        return 1
    print("Verified original development-attestation backup; device restoration is a separate step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
