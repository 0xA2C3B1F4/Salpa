#!/usr/bin/env python3
"""Generate a development-only RissoKey attestation key and certificate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier


AAGUID = bytes.fromhex("989e2cc205df4e64806822683886e8b3")
AAGUID_TEXT = "989e2cc2-05df-4e64-8068-22683886e8b"
AAGUID_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


def write_new(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def build_certificate(private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FI"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RissoKey Development"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            x509.NameAttribute(NameOID.COMMON_NAME, "RissoKey Development Attestation"),
        ]
    )
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), False)
        .add_extension(x509.UnrecognizedExtension(AAGUID_OID, b"\x04\x10" + AAGUID), False)
        .sign(private_key, hashes.SHA256())
    )


def verify_pair(
    private_key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate
) -> None:
    extension = certificate.extensions.get_extension_for_oid(AAGUID_OID)
    if extension.value.value != b"\x04\x10" + AAGUID:
        raise RuntimeError("generated certificate has an invalid AAGUID extension")
    if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
        raise RuntimeError("generated certificate does not match the private key")
    certificate.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        ec.ECDSA(certificate.signature_hash_algorithm),
    )


def main() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_directory",
        type=Path,
        help="new protected directory; it must not already exist",
    )
    parser.add_argument("--quiet", action="store_true", help="Do not print certificate fingerprints or material locations")
    args = parser.parse_args()
    output_directory = args.output_directory.expanduser().resolve()
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)

    private_key = ec.generate_private_key(ec.SECP256R1())
    certificate = build_certificate(private_key)
    verify_pair(private_key, certificate)

    raw_key = private_key.private_numbers().private_value.to_bytes(32, "big")
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

    write_new(output_directory / "attestation-key.raw", raw_key, 0o600)
    write_new(output_directory / "attestation-cert.der", cert_der, 0o644)
    write_new(output_directory / "attestation-cert.pem", cert_pem, 0o644)

    manifest = {
        "purpose": "RissoKey development attestation only",
        "aaguid": AAGUID_TEXT,
        "certificate_sha256": hashlib.sha256(cert_der).hexdigest(),
        "private_key_file": "attestation-key.raw",
        "certificate_file": "attestation-cert.der",
    }
    write_new(
        output_directory / "manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        0o644,
    )

    if not args.quiet:
        print(f"Created development attestation material in {output_directory}")
        print(f"AAGUID: {AAGUID_TEXT}")
        print(f"Certificate SHA-256: {manifest['certificate_sha256']}")
        print("Protect attestation-key.raw and any provisioning build that embeds it.")


if __name__ == "__main__":
    main()
