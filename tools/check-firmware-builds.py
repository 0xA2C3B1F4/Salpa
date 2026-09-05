#!/usr/bin/env python3
"""Build and lint public fixtures without signing, packaging or device access.

The synthetic USB identity and signing digest are not deployment inputs.
No output from this command may be installed on an account key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from host_common import sha256_file

PROFILES = {
    "s2-development": ("esp32s2", "legacy-0x8000", "rissokey", ["ctaphid-bringup", "fido-stack", "mcu-esp32s2"]),
    "s2-protected": ("esp32s2", "signed-ab-encrypted", "rissokey", ["ctaphid-bringup", "fido-stack", "mcu-esp32s2", "non-strapping-user-presence", "release-flash-encryption", "signed-ab-update", "usb-signed-update"]),
    "s3-bringup": ("esp32s3", "legacy-0x8000", "rissokey", ["ctaphid-bringup", "fido-stack", "mcu-esp32s3"]),
    "s2-attestation-import": ("esp32s2", "signed-ab-encrypted", "import-attestation", ["attestation-import", "mcu-esp32s2", "non-strapping-user-presence", "release-flash-encryption"]),
    "s2-storage-provision": ("esp32s2", "signed-ab-encrypted", "provision-storage", ["storage-provisioning", "mcu-esp32s2", "non-strapping-user-presence", "release-flash-encryption"]),
    "s2-development-provision": ("esp32s2", "legacy-0x8000", "provision-development", ["development-provisioning", "mcu-esp32s2"]),
    "s2-storage-powercut": ("esp32s2", "legacy-0x8000", "storage-powercut-test", ["physical-storage-fault-test", "mcu-esp32s2"]),
}


def fixture_environment(destination: Path, profile: tuple, inherited: dict) -> dict:
    mcu, partition, binary, features = profile
    env = {key: value for key, value in inherited.items()
           if not key.startswith(("RISSO_KEY_", "ESP_BOOTLOADER_ESP_IDF_CONFIG_"))}
    env.update({
        "CARGO_TARGET_DIR": str(destination / "target"),
        "RISSO_KEY_MCU": mcu,
        "RISSO_KEY_PARTITION_PROFILE": partition,
        "RISSO_KEY_USB_VID": "0x1209",
        "RISSO_KEY_USB_PID": "1",
        "RISSO_KEY_USB_SERIAL": "CI-COMPILE-ONLY",
        "RISSO_KEY_UPDATE_KEY_DIGEST_HEX": hashlib.sha256(b"public compile-only fixture").hexdigest(),
        "ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION": "3",
    })
    if binary == "import-attestation":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        # Public scalar-one test fixture, unrelated to any device identity.
        public = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        public_path = destination / "compile-only-public.sec1"
        digest_path = destination / "compile-only-certificate.sha256"
        public_path.write_bytes(public)
        digest_path.write_bytes(hashlib.sha256(b"compile-only certificate").digest())
        env.update({
            "RISSO_KEY_ATTESTATION_IMPORT_ACK": "INSTALL_ATTESTATION",
            "RISSO_KEY_ATTESTATION_PUBLIC_FILE": str(public_path),
            "RISSO_KEY_ATTESTATION_CERT_SHA256_FILE": str(digest_path),
        })
    if binary in ("provision-storage", "provision-development"):
        env["RISSO_KEY_PROVISIONING_ACK"] = "ERASE_FIDO_STORE"
    if binary == "storage-powercut-test":
        env["RISSO_KEY_PHYSICAL_FAULT_TEST_ACK"] = "INTERRUPT_FIDO_STORE"
    if binary == "provision-development":
        # Known scalar 1 and an AAGUID-shaped byte fixture, not an X.509
        # certificate or generated identity. Keeping the early scalar/AAGUID
        # assertions satisfiable lets the linker check the provisioning code.
        # This data cannot pass the later attestation certificate verification.
        scalar_path = destination / "compile-only-scalar-one.raw"
        certificate_path = destination / "compile-only-not-a-certificate.fixture"
        scalar_path.write_bytes(bytes(31) + b"\x01")
        certificate_path.write_bytes(bytes.fromhex(
            "060b2b0601040182e51c01010404120410"
            "989e2cc205df4e64806822683886e8b3"))
        env["RISSO_KEY_DEV_ATTESTATION_KEY"] = str(scalar_path)
        env["RISSO_KEY_DEV_ATTESTATION_CERT"] = str(certificate_path)
    return env


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--profile", choices=["all", *PROFILES], default="all")
    parser.add_argument("--check", choices=["all", "build", "clippy"], default="all")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    destination = args.build_dir.expanduser().resolve()
    if destination.is_relative_to(root):
        parser.error("build directory must be outside the repository")
    destination.mkdir(parents=True, exist_ok=False)
    profiles = PROFILES if args.profile == "all" else {args.profile: PROFILES[args.profile]}
    results = []
    for name, (mcu, partition, binary, features) in profiles.items():
        env = fixture_environment(destination, PROFILES[name], dict(os.environ))
        checks = ("build", "clippy") if args.check == "all" else (args.check,)
        for check in checks:
            command = ["./tools/cargo-esp", check, "--locked", "--release",
                       "--no-default-features", "--features", ",".join(features), "--bin", binary]
            if check == "clippy":
                command += ["--", "-D", "warnings"]
            log_path = destination / f"{name}-{check}.log"
            with log_path.open("w") as log:
                result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                raise SystemExit(f"{name} {check} failed; inspect {log_path}")
            record = {"profile": name, "check": check, "command": command, "passed": True}
            if check == "build":
                elf = destination / "target" / f"xtensa-{mcu}-none-elf" / "release" / binary
                record.update(elf_bytes=elf.stat().st_size, elf_sha256=sha256_file(elf))
            results.append(record)
            print(f"PASS: {name} {check}, compile-only fixture", flush=True)
    (destination / "build-results.json").write_text(json.dumps({
        "schema": 1, "kind": "public-fixture-target-builds", "results": results,
        "device_accessed": False, "installable_package_created": False,
        "operational_keys_used": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
