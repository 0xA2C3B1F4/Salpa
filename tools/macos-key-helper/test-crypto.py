#!/usr/bin/env python3
"""Run with the pinned Espressif Python. Uses disposable public test material."""
import hashlib
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import resource
from unittest import mock
from datetime import datetime, timedelta, timezone
import espsecure
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID, ObjectIdentifier
import base64
import json

root = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="rissokey-key-helper-test-") as tmp:
    folder = Path(tmp)
    for address in (0, 16, 112, 0x1000, 0x20000, 0x200000):
        output = io.BytesIO()
        espsecure._flash_encryption_operation_aes_xts(output, io.BytesIO(bytes(range(256))), address, io.BytesIO(bytes(range(32))), False)
        (folder / f"xts-{address}.bin").write_bytes(output.getvalue())
    (folder / "pbkdf2.bin").write_bytes(hashlib.pbkdf2_hmac("sha256", b"test-only-public-passphrase", bytes([42])*32, 600000, 32))
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pem = folder / "test-key.pem"
    pem.touch(mode=0o600)
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # Public fixed fixture scalars: these are never a device identity.
    for scalar in (1, 2, 3, 4, 5):
        fixture_key = ec.derive_private_key(scalar, ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PUBLIC TEST FIXTURE ONLY")])
        today = datetime.now(timezone.utc)
        certificate_builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(fixture_key.public_key()).serial_number(scalar)
            .not_valid_before(today - timedelta(days=1)).not_valid_after(today + timedelta(days=1)))
        if scalar != 4:
            aaguid = bytes(16) if scalar == 3 else bytes.fromhex("989e2cc205df4e64806822683886e8b3")
            certificate_builder = certificate_builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"), b"\x04\x10" + aaguid), critical=scalar == 5)
        certificate = certificate_builder.sign(fixture_key, hashes.SHA256())
        der = certificate.public_bytes(serialization.Encoding.DER)
        (folder / f"fixture-{scalar}.der").write_bytes(der)
        if scalar == 1:
            attestation_payload = b"RKATST01" + len(der).to_bytes(4, "little") + bytes(4) + scalar.to_bytes(32, "big") + der
            attestation_payload += bytes(4096 - len(attestation_payload))
            (folder / "attestation-payload.bin").write_bytes(attestation_payload)
            output = io.BytesIO()
            espsecure._flash_encryption_operation_aes_xts(output, io.BytesIO(attestation_payload), 0x200000, io.BytesIO(bytes(range(32))), False)
            (folder / "attestation-xts.bin").write_bytes(output.getvalue())
    (folder / "main.swift").write_text((root / "main.swift").read_text() + (root / "test.swift.inc").read_text())
    subprocess.run(["swiftc", "-suppress-warnings", "-O", "-D", "KEY_HELPER_TEST", "-module-cache-path", str(folder / "module-cache"), str(folder / "main.swift"), "-o", str(folder / "test-helper")], check=True)
    subprocess.run([str(folder / "test-helper"), str(folder)], check=True)
    subprocess.run([str(folder / "test-helper"), str(folder), "restore-attestation-fixture"], check=True)
    envelope = json.loads((folder / "attestation-backup.json").read_text())
    salt = base64.b64decode(envelope["salt"])
    derived = hashlib.pbkdf2_hmac("sha256", b"test-only-public-passphrase", salt, 600000, 32)
    aad = "|".join(envelope[field] for field in ("format", "role", "certificateSHA256", "publicKeyX963SHA256")).encode()
    sealed = base64.b64decode(envelope["sealed"])
    assert AESGCM(derived).decrypt(sealed[:12], sealed[12:], aad) == attestation_payload
    print("PASS: separate-process attestation restore; Python authenticated backup decryption; exact staging contract")
    key.public_key().verify((folder / "test.sig").read_bytes(), bytes(range(256)), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    print("PASS: Swift RSA-PSS verified by cryptography with Espressif salt length 32")
    spec = importlib.util.spec_from_file_location("attestation_generator", root.parent / "generate-dev-attestation.py")
    generator = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(generator)
    generated = folder / "public-fixture-generator-output"
    stdout = io.StringIO()
    with mock.patch("sys.argv", ["generate-dev-attestation.py", "--quiet", str(generated)]), mock.patch.object(generator.ec, "generate_private_key", return_value=ec.derive_private_key(1, ec.SECP256R1())), contextlib.redirect_stdout(stdout):
        generator.main()
    assert stdout.getvalue() == ""
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
    assert (generated / "attestation-key.raw").read_bytes() == (1).to_bytes(32, "big")
    assert (generated / "attestation-key.raw").stat().st_mode & 0o777 == 0o600
    assert generated.stat().st_mode & 0o777 == 0o700
    manifest = json.loads((generated / "manifest.json").read_text())
    assert manifest["certificate_sha256"] == hashlib.sha256((generated / "attestation-cert.der").read_bytes()).hexdigest()
    print("PASS: quiet generator and disabled core dumps, using only public scalar-one fixture")
