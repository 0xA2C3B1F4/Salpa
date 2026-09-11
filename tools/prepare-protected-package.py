#!/usr/bin/env python3
"""Prepare a signed, offset-encrypted ESP32-S2 recovery package off-device."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import git_output, is_within, sha256_file
from keychain_backend import DEFAULT_HELPER, KeychainSigningKey, KeychainFlashKey


ESPFLASH_VERSION = "espflash 4.5.0"
ESPTOOL_VERSION = "5.4.0"
BOOTLOADER_OFFSET = 0x1000
TABLE_OFFSET = 0xE000
OTA_OFFSETS = {"ota_0": 0x20000, "ota_1": 0x200000}
OTA_SIZE = 0x1E0000
FLASH_KEY_BYTES = 32
APPLICATION_CONTRACTS = {
    "runtime": {
        "features": {
            "ctaphid-bringup",
            "fido-stack",
            "mcu-esp32s2",
            "non-strapping-user-presence",
            "release-flash-encryption",
            "signed-ab-update",
            "usb-signed-update",
        },
        "image": "runtime",
        "image_version": None,
        "runtime_variant": "normal",
    },
    "rollback-failure": {
        "features": {
            "ctaphid-bringup",
            "fido-stack",
            "mcu-esp32s2",
            "non-strapping-user-presence",
            "release-flash-encryption",
            "signed-ab-failure-test",
            "signed-ab-update",
            "usb-signed-update",
        },
        "image": "runtime",
        "image_version": "0.1.1-ab-fail",
        "runtime_variant": "rollback-failure",
    },
    "storage-provisioner": {
        "features": {
            "mcu-esp32s2",
            "non-strapping-user-presence",
            "release-flash-encryption",
            "storage-provisioning",
        },
        "image": "storage-provisioner",
        "image_version": None,
        "runtime_variant": None,
    },
}


class PackageError(RuntimeError):
    """Protected-package provenance, signing, or encryption validation failed."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def command_output(*args: str) -> str:
    return subprocess.run(list(args), check=True, capture_output=True, text=True).stdout.strip()


def regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"{label} must be an existing regular file")


def executable_file(path: Path, label: str) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PackageError(f"{label} must be an executable file")


def load_manifest(path: Path, kind: str) -> dict[str, object]:
    regular_file(path, "build manifest")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackageError(f"cannot read {path.name}: {error}") from error
    if not isinstance(document, dict):
        raise PackageError(f"manifest must contain a JSON object: {path.name}")
    if document.get("schema") != 1 or document.get("kind") != kind:
        raise PackageError(f"unexpected manifest kind or schema: {path.name}")
    return document


def manifest_artifact(manifest_path: Path, record: object) -> Path:
    if not isinstance(record, dict):
        raise PackageError(f"invalid artifact record in {manifest_path.name}")
    relative = record.get("file")
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise PackageError(f"invalid artifact path in {manifest_path.name}")
    base = manifest_path.parent.resolve()
    artifact = (base / relative).resolve()
    if not is_within(artifact, base):
        raise PackageError("artifact escapes its build directory")
    regular_file(artifact, "build artifact")
    if (
        record.get("size") != artifact.stat().st_size
        or record.get("sha256") != sha256_file(artifact)
    ):
        raise PackageError(f"artifact does not match {manifest_path.name}")
    return artifact


def sign_image(python: Path, private_key: KeychainSigningKey, source: Path, output: Path) -> None:
    private_key.sign_image(python, source, output)


def verify_signature(python: Path, public_key: Path, image: Path) -> None:
    result = subprocess.run(
        [
            str(python),
            "-m",
            "espsecure",
            "verify-signature",
            "--version",
            "2",
            "--keyfile",
            str(public_key),
            str(image),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PackageError("espsecure rejected a signed package image")


def public_key_digest(python: Path, public_key: Path, temporary: Path) -> str:
    subprocess.run(
        [
            str(python),
            "-m",
            "espsecure",
            "digest-rsa-public-key",
            "--keyfile",
            str(public_key),
            "--output",
            str(temporary),
        ],
        check=True,
    )
    digest = temporary.read_bytes()
    temporary.unlink()
    if len(digest) != 32:
        raise PackageError("unexpected Secure Boot public-key digest size")
    return digest.hex()


def encrypt_at_offset(
    python: Path,
    flash_key: KeychainFlashKey,
    plaintext: Path,
    ciphertext: Path,
    address: int,
) -> None:
    flash_key.encrypt(plaintext, ciphertext, address)


def record_file(path: Path) -> dict[str, object]:
    return {"file": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sign protected ESP32-S2 images and AES-XTS encrypt every flash "
            "artifact for its exact destination offset without touching hardware."
        )
    )
    parser.add_argument("--espflash", required=True, type=Path)
    parser.add_argument("--esptool-python", required=True, type=Path)
    parser.add_argument("--bootloader-manifest", required=True, type=Path)
    parser.add_argument("--runtime-manifest", required=True, type=Path)
    parser.add_argument("--rollback-failure-manifest", required=True, type=Path)
    parser.add_argument("--provisioner-manifest", required=True, type=Path)
    parser.add_argument("--key-helper", type=Path, default=DEFAULT_HELPER)
    parser.add_argument("--signing-public-key", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    root = repository_root()
    espflash = args.espflash.expanduser().resolve()
    python = args.esptool_python.expanduser().absolute()
    output_dir = args.output_dir.expanduser().resolve()
    manifest_paths = {
        "bootloader": args.bootloader_manifest.expanduser().resolve(),
        "runtime": args.runtime_manifest.expanduser().resolve(),
        "rollback-failure": args.rollback_failure_manifest.expanduser().resolve(),
        "storage-provisioner": args.provisioner_manifest.expanduser().resolve(),
    }
    signing_public = args.signing_public_key.expanduser().resolve()
    try:
        signing_private = KeychainSigningKey(args.key_helper, signing_public)
        flash_key = KeychainFlashKey(args.key_helper)
        if is_within(output_dir, root):
            raise PackageError("package and secret keys must stay outside Git")
        if output_dir.exists() and any(output_dir.iterdir()):
            raise PackageError("output directory must be new or empty")
        executable_file(espflash, "espflash")
        executable_file(python, "Espressif Python")
        regular_file(signing_public, "signing public key")
        public_data = signing_public.read_bytes()
        if b"PRIVATE KEY" in public_data or b"PUBLIC KEY" not in public_data:
            raise PackageError("signing public key must be a public-only PEM file")
        if command_output(str(espflash), "--version").splitlines()[0] != ESPFLASH_VERSION:
            raise PackageError(f"espflash must be exactly {ESPFLASH_VERSION}")
        result = subprocess.run(
            [str(python), "-c", "import esptool; print(esptool.__version__)"],
            check=True,
            capture_output=True,
            text=True,
        )
        if result.stdout.strip() != ESPTOOL_VERSION:
            raise PackageError(f"esptool must be exactly {ESPTOOL_VERSION}")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise PackageError("source tree must be clean before packaging")
        subprocess.run(
            [sys.executable, str(root / "scripts/check_partition_layouts.py")], check=True
        )
        subprocess.run(
            [sys.executable, str(root / "scripts/check_efuse_plan.py")], check=True
        )

        source_commit = git_output(root, "rev-parse", "HEAD")
        source_tree = git_output(root, "rev-parse", "HEAD^{tree}")
        partition_hash = sha256_file(root / "partitions-ab-encrypted.csv")
        plan_hash = sha256_file(root / "policy/esp32s2-protected-efuse-plan.json")

        boot_manifest = load_manifest(
            manifest_paths["bootloader"], "rissokey-protected-bootloader"
        )
        protection = boot_manifest.get("protection")
        verification = boot_manifest.get("custom_boot_verification")
        if (
            boot_manifest.get("source_commit") != source_commit
            or boot_manifest.get("source_tree") != source_tree
            or boot_manifest.get("build_only") is not True
            or boot_manifest.get("efuse_operations_performed") is not False
            or boot_manifest.get("security_profile")
            != "wemos-s2-mini-protected-prototype"
            or not isinstance(protection, dict)
            or protection.get("external_efuse_plan_required") is not True
            or protection.get("flash_encryption") != "release"
            or protection.get("secure_boot") != "v2-rsa3072"
            or not isinstance(verification, dict)
        ):
            raise PackageError("bootloader evidence has the wrong protected contract")
        boot_artifacts = boot_manifest.get("artifacts")
        if not isinstance(boot_artifacts, dict):
            raise PackageError("bootloader manifest has no artifact map")
        bootloader = manifest_artifact(
            manifest_paths["bootloader"], boot_artifacts.get("bootloader_bin")
        )

        applications: dict[str, Path] = {}
        application_manifests: dict[str, dict[str, object]] = {}
        for image, path in manifest_paths.items():
            if image == "bootloader":
                continue
            contract = APPLICATION_CONTRACTS[image]
            manifest = load_manifest(path, "rissokey-protected-application")
            source = manifest.get("source")
            build = manifest.get("build")
            features = build.get("features") if isinstance(build, dict) else None
            if (
                manifest.get("image") != contract["image"]
                or manifest.get("runtime_variant") != contract["runtime_variant"]
                or manifest.get("image_version") != contract["image_version"]
                or type(manifest.get("secure_version")) is not int
                or not 0 <= manifest["secure_version"] <= 16
                or manifest.get("build_only") is not True
                or manifest.get("efuse_operations_performed") is not False
                or not isinstance(source, dict)
                or source.get("commit") != source_commit
                or source.get("tree") != source_tree
                or source.get("partition_table_sha256") != partition_hash
                or source.get("efuse_plan_sha256") != plan_hash
                or not isinstance(build, dict)
                or build.get("partition_profile") != "signed-ab-encrypted"
                or build.get("security_profile")
                != "wemos-s2-mini-protected-prototype"
                or not isinstance(features, list)
                or set(features) != contract["features"]
            ):
                raise PackageError(f"{image} evidence has the wrong protected contract")
            applications[image] = manifest_artifact(path, manifest.get("artifact"))
            application_manifests[image] = manifest

        output_dir.mkdir(parents=True, exist_ok=True)
        output_dir.chmod(0o700)
        digest = public_key_digest(python, signing_public, output_dir / ".key-digest")
        if verification.get("public_key_digest") != digest:
            raise PackageError("bootloader trust root does not match the signing key")
        if application_manifests["runtime"].get("trusted_public_key_digest") != digest:
            raise PackageError("runtime update trust root does not match the signing key")
        if (
            application_manifests["rollback-failure"].get(
                "trusted_public_key_digest"
            )
            != digest
        ):
            raise PackageError(
                "rollback-failure update trust root does not match the signing key"
            )
        if application_manifests["storage-provisioner"].get(
            "trusted_public_key_digest"
        ) is not None:
            raise PackageError("storage provisioner must not contain a runtime update key")
        if application_manifests["rollback-failure"].get(
            "secure_version"
        ) != application_manifests["runtime"].get("secure_version"):
            raise PackageError(
                "rollback-failure and normal runtime must use the same secure version"
            )

        signed_bootloader = output_dir / ".bootloader-signed.bin"
        sign_image(python, signing_private, bootloader, signed_bootloader)
        verify_signature(python, signing_public, signed_bootloader)
        if signed_bootloader.stat().st_size > TABLE_OFFSET - BOOTLOADER_OFFSET:
            raise PackageError("signed bootloader overlaps the partition table")
        encrypted_bootloader = output_dir / "bootloader-signed-encrypted.bin"
        encrypt_at_offset(
            python, flash_key, signed_bootloader, encrypted_bootloader, BOOTLOADER_OFFSET
        )
        signed_bootloader.unlink()

        plaintext_table = output_dir / ".partition-table.bin"
        subprocess.run(
            [
                str(espflash),
                "partition-table",
                "--to-binary",
                "--output",
                str(plaintext_table),
                str(root / "partitions-ab-encrypted.csv"),
            ],
            check=True,
        )
        if plaintext_table.stat().st_size != 0xC00:
            raise PackageError("generated partition table must be exactly 0xC00 bytes")
        encrypted_table = output_dir / "partition-table-encrypted.bin"
        encrypt_at_offset(
            python, flash_key, plaintext_table, encrypted_table, TABLE_OFFSET
        )
        plaintext_table.unlink()

        encrypted_applications: dict[str, dict[str, Path]] = {}
        runtime_usb_image: Path | None = None
        rollback_failure_usb_image: Path | None = None
        for image, elf in applications.items():
            unsigned = output_dir / f".{image}-unsigned.bin"
            signed = output_dir / f".{image}-signed.bin"
            subprocess.run(
                [
                    str(espflash),
                    "save-image",
                    "--chip",
                    "esp32s2",
                    "--flash-freq",
                    "40mhz",
                    "--flash-mode",
                    "dio",
                    "--flash-size",
                    "4mb",
                    "--bootloader",
                    str(bootloader),
                    "--partition-table",
                    str(root / "partitions-ab-encrypted.csv"),
                    "--partition-table-offset",
                    hex(TABLE_OFFSET),
                    "--target-app-partition",
                    "ota_0",
                    str(elf),
                    str(unsigned),
                ],
                check=True,
            )
            sign_image(python, signing_private, unsigned, signed)
            verify_signature(python, signing_public, signed)
            unsigned.unlink()
            if signed.stat().st_size > OTA_SIZE:
                raise PackageError(f"signed {image} image exceeds an OTA slot")
            signed_prefix = signed.read_bytes()[:80]
            if (
                len(signed_prefix) != 80
                or int.from_bytes(signed_prefix[32:36], "little") != 0xABCD5432
                or int.from_bytes(signed_prefix[36:40], "little")
                != application_manifests[image]["secure_version"]
            ):
                raise PackageError(
                    f"signed {image} secure version differs from build evidence"
                )
            if image == "runtime":
                runtime_usb_image = output_dir / "runtime-usb-signed.bin"
                shutil.copy2(signed, runtime_usb_image)
            elif image == "rollback-failure":
                rollback_failure_usb_image = (
                    output_dir / "rollback-failure-usb-signed.bin"
                )
                shutil.copy2(signed, rollback_failure_usb_image)
            encrypted_applications[image] = {}
            for slot, offset in OTA_OFFSETS.items():
                encrypted = output_dir / f"{image}-{slot}-signed-encrypted.bin"
                encrypt_at_offset(python, flash_key, signed, encrypted, offset)
                encrypted_applications[image][slot] = encrypted
            signed.unlink()

        if runtime_usb_image is None:
            raise PackageError("runtime USB update image was not produced")
        if rollback_failure_usb_image is None:
            raise PackageError("rollback-failure USB update image was not produced")

        copies = {
            "bootloader-build.json": manifest_paths["bootloader"],
            "runtime-build.json": manifest_paths["runtime"],
            "rollback-failure-build.json": manifest_paths["rollback-failure"],
            "storage-provisioner-build.json": manifest_paths["storage-provisioner"],
            "trusted-public-key.pem": signing_public,
        }
        for name, source in copies.items():
            shutil.copy2(source, output_dir / name)

        outputs = [
            encrypted_bootloader,
            encrypted_table,
            runtime_usb_image,
            rollback_failure_usb_image,
        ]
        outputs.extend(
            encrypted_applications[image][slot]
            for image in ("runtime", "rollback-failure", "storage-provisioner")
            for slot in OTA_OFFSETS
        )
        outputs.extend(output_dir / name for name in copies)
        files = {path.name: record_file(path) for path in outputs}
        writes = {
            "bootloader": {
                **files[encrypted_bootloader.name],
                "offset": BOOTLOADER_OFFSET,
            },
            "partition_table": {
                **files[encrypted_table.name],
                "offset": TABLE_OFFSET,
            },
        }
        for image in ("runtime", "rollback-failure", "storage-provisioner"):
            for slot, offset in OTA_OFFSETS.items():
                path = encrypted_applications[image][slot]
                writes[f"{image}_{slot}"] = {**files[path.name], "offset": offset}

        package = {
            "created_at": datetime.now(UTC).isoformat(),
            "device_preconditions": {
                "chip": "esp32s2",
                "efuse_readback_profile": "pristine",
                "flash_bytes": 0x400000,
            },
            "efuse_operations_performed": False,
            "files": files,
            "flash_authorized": False,
            "flash_encryption": {
                "algorithm": "AES-128-XTS",
                "exact_destination_offset_required": True,
                "key_bytes": FLASH_KEY_BYTES,
                "key_fingerprint_recorded": False,
                "key_included": False,
            },
            "install_sets": {
                "initial_storage_provisioner": [
                    "bootloader",
                    "partition_table",
                    "storage-provisioner_ota_0",
                ],
                "runtime_with_existing_attestation": ["runtime_ota_0"],
                "runtime_recovery": ["bootloader", "partition_table", "runtime_ota_0"],
            },
            "install_set_preconditions": {
                "initial_storage_provisioner": [
                    "Verify recoverability of the original attestation key and certificate before erasing fido_store",
                    "Storage initialization alone does not install attestation or make FIDO ready",
                ],
                "runtime_with_existing_attestation": [
                    "Original attestation key and certificate already restored in encrypted fido_store",
                    "Boot metadata selects ota_0",
                ],
                "runtime_recovery": [
                    "Preserve existing encrypted fido_store with its original attestation identity",
                    "Boot metadata selects ota_0; this install set does not repair a selected ota_1",
                ],
            },
            "kind": "rissokey-protected-package",
            "layout": {
                "ota_slot_size": OTA_SIZE,
                "partition_csv_sha256": partition_hash,
            },
            "usb_update": {
                **files[runtime_usb_image.name],
                "plaintext_signed_image": True,
                "target_selected_by_device": True,
                "written_encrypted_by_device": True,
            },
            "test_fixtures": {
                "rollback_failure": {
                    **files[rollback_failure_usb_image.name],
                    "expected_first_boot_confirmation": False,
                    "plaintext_signed_image": True,
                    "secure_version": application_manifests["rollback-failure"][
                        "secure_version"
                    ],
                    "target_selected_by_device": True,
                    "written_encrypted_by_device": True,
                }
            },
            "private_signing_key_included": False,
            "schema": 2,
            "secure_boot": {
                "algorithm": "RSA-3072-PSS-SHA256",
                "public_key_digest": digest,
                "signed_before_flash_encryption": True,
            },
            "security_profile": "wemos-s2-mini-protected-prototype",
            "source": {
                "commit": source_commit,
                "efuse_plan_sha256": plan_hash,
                "tree": source_tree,
            },
            "verification": {
                "all_ciphertexts_round_trip_at_recorded_offset": True,
                "all_executable_signatures_verified_before_encryption": True,
                "fido_store_image_included": False,
                "otadata_image_included": False,
                "rollback_failure_signature_verified": True,
                "usb_update_signature_verified": True,
            },
            "writes": writes,
        }
        package_path = output_dir / "rissokey-protected-package.json"
        package_path.write_text(
            json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        package_path.chmod(0o600)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"protected package failed: {error}", file=sys.stderr)
        return 1

    print(f"prepared host-only protected package at {output_dir}")
    print("secret keys were not copied; nothing was flashed and no eFuse was changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
