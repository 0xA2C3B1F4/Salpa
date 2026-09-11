#!/usr/bin/env python3
"""Prepare a hash-bound signed A/B device-test package off-device."""

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
from keychain_backend import DEFAULT_HELPER, KeychainSigningKey


ESPFLASH_VERSION = "espflash 4.5.0"
ESPTOOL_VERSION = "5.4.0"
BOOTLOADER_OFFSET = 0x1000
TABLE_OFFSET = 0xE000
OTA_0_OFFSET = 0x20000
OTA_1_OFFSET = 0x200000
OTA_SIZE = 0x1E0000
FIDO_STORE_OFFSET = 0x3E0000
FIDO_STORE_SIZE = 0x20000


class PackageError(RuntimeError):
    """Signed A/B package provenance or layout validation failed."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def command_output(*args: str) -> str:
    return subprocess.run(list(args), check=True, capture_output=True, text=True).stdout.strip()


def regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise PackageError(f"{label} must be a regular file: {path}")


def executable_file(path: Path, label: str) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PackageError(f"{label} must be an executable file: {path}")


def load_manifest(path: Path, kind: str) -> dict[str, object]:
    regular_file(path, "build manifest")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackageError(f"cannot read {path}: {error}") from error
    if not isinstance(document, dict):
        raise PackageError(f"manifest must contain a JSON object: {path}")
    if document.get("schema") != 1 or document.get("kind") != kind:
        raise PackageError(f"unexpected manifest kind or schema: {path}")
    return document


def manifest_artifact(manifest_path: Path, record: object) -> Path:
    if not isinstance(record, dict):
        raise PackageError(f"invalid artifact record in {manifest_path}")
    relative = record.get("file")
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise PackageError(f"invalid artifact path in {manifest_path}")
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


def sign_image(python: Path, private_key: Path | KeychainSigningKey, source: Path, output: Path) -> None:
    if isinstance(private_key, KeychainSigningKey):
        private_key.sign_image(python, source, output)
        return
    subprocess.run(
        [
            str(python),
            "-m",
            "espsecure",
            "sign-data",
            "--version",
            "2",
            "--keyfile",
            str(private_key),
            "--output",
            str(output),
            str(source),
        ],
        check=True,
    )


def verify_image(python: Path, public_key: Path, image: Path, *, expect_valid: bool) -> None:
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
    if expect_valid and result.returncode != 0:
        raise PackageError("espsecure rejected a package signature")
    if not expect_valid and result.returncode == 0:
        raise PackageError("trusted public key unexpectedly accepted the untrusted image")


def key_digest(python: Path, public_key: Path, output: Path) -> str:
    subprocess.run(
        [
            str(python),
            "-m",
            "espsecure",
            "digest-rsa-public-key",
            "--keyfile",
            str(public_key),
            "--output",
            str(output),
        ],
        check=True,
    )
    digest = output.read_bytes()
    output.unlink()
    if len(digest) != 32:
        raise PackageError("unexpected public-key digest size")
    return digest.hex()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--espflash", required=True, type=Path)
    parser.add_argument("--esptool-python", required=True, type=Path)
    parser.add_argument("--bootloader-manifest", required=True, type=Path)
    parser.add_argument("--base-manifest", required=True, type=Path)
    parser.add_argument("--failure-manifest", required=True, type=Path)
    parser.add_argument("--success-manifest", required=True, type=Path)
    parser.add_argument("--key-helper", type=Path, default=DEFAULT_HELPER)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--untrusted-private-key", required=True, type=Path)
    parser.add_argument("--untrusted-public-key", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--security-profile",
        choices=(
            "wemos-s2-mini-non-strapping-up-test",
            "wemos-s2-mini-signed-ab-test",
        ),
        default="wemos-s2-mini-signed-ab-test",
    )
    args = parser.parse_args()

    root = repository_root()
    espflash = args.espflash.expanduser().resolve()
    # Preserve virtual-environment interpreter symlinks: resolving the symlink can
    # select the base interpreter and silently change the installed Espressif tools.
    python = args.esptool_python.expanduser().absolute()
    output_dir = args.output_dir.expanduser().resolve()
    boot_path = args.bootloader_manifest.expanduser().resolve()
    app_paths = {
        "base": args.base_manifest.expanduser().resolve(),
        "failure": args.failure_manifest.expanduser().resolve(),
        "success": args.success_manifest.expanduser().resolve(),
    }
    key_paths = {
        "trusted_public": args.trusted_public_key.expanduser().resolve(),
        "untrusted_private": args.untrusted_private_key.expanduser().resolve(),
        "untrusted_public": args.untrusted_public_key.expanduser().resolve(),
    }

    try:
        trusted_signer = KeychainSigningKey(args.key_helper, key_paths["trusted_public"])
        if is_within(output_dir, root) or any(is_within(path, root) for path in key_paths.values()):
            raise PackageError("package and signing keys must stay outside Git")
        if output_dir.exists() and any(output_dir.iterdir()):
            raise PackageError("output directory must be new or empty")
        regular_file(espflash, "espflash")
        executable_file(python, "Espressif Python")
        for name, path in key_paths.items():
            regular_file(path, name.replace("_", " "))
        for name in ("untrusted_private",):
            if b"PRIVATE KEY" not in key_paths[name].read_bytes():
                raise PackageError(f"{name.replace('_', ' ')} is not a PEM private key")
        for name in ("trusted_public", "untrusted_public"):
            data = key_paths[name].read_bytes()
            if b"PRIVATE KEY" in data or b"PUBLIC KEY" not in data:
                raise PackageError(f"{name.replace('_', ' ')} is not a public-only PEM key")
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
        subprocess.run([sys.executable, str(root / "scripts/check_partition_layouts.py")], check=True)

        source_commit = git_output(root, "rev-parse", "HEAD")
        source_tree = git_output(root, "rev-parse", "HEAD^{tree}")
        boot_manifest = load_manifest(boot_path, "rissokey-signed-ab-bootloader")
        if (
            boot_manifest.get("source_commit") != source_commit
            or boot_manifest.get("source_tree") != source_tree
        ):
            raise PackageError("bootloader evidence belongs to another source revision")
        boot_artifacts = boot_manifest.get("artifacts")
        if not isinstance(boot_artifacts, dict):
            raise PackageError("bootloader manifest has no artifact map")
        bootloader = manifest_artifact(boot_path, boot_artifacts.get("bootloader_bin"))

        app_elfs: dict[str, Path] = {}
        app_manifests: dict[str, dict[str, object]] = {}
        expect_non_strapping = (
            args.security_profile == "wemos-s2-mini-non-strapping-up-test"
        )
        for variant, manifest_path in app_paths.items():
            manifest = load_manifest(manifest_path, "rissokey-signed-ab-application")
            source = manifest.get("source")
            build = manifest.get("build")
            features = build.get("features") if isinstance(build, dict) else None
            if (
                manifest.get("variant") != variant
                or type(manifest.get("secure_version")) is not int
                or not 0 <= manifest["secure_version"] <= 0xFFFF_FFFF
                or not isinstance(manifest.get("image_version"), str)
                or not 1 <= len(manifest["image_version"].encode("utf-8")) <= 31
                or not isinstance(source, dict)
                or source.get("commit") != source_commit
                or source.get("tree") != source_tree
                or source.get("partition_table_sha256") != sha256_file(root / "partitions-ab.csv")
                or not isinstance(build, dict)
                or build.get("partition_profile") != "signed-ab"
                or build.get("security_profile") != args.security_profile
                or not isinstance(features, list)
                or ("non-strapping-user-presence" in features) != expect_non_strapping
                or "usb-signed-update" not in features
            ):
                raise PackageError(f"{variant} application evidence has the wrong contract")
            app_elfs[variant] = manifest_artifact(manifest_path, manifest.get("artifact"))
            app_manifests[variant] = manifest

        output_dir.mkdir(parents=True, exist_ok=True)
        trusted_digest = key_digest(python, key_paths["trusted_public"], output_dir / ".digest")
        untrusted_digest = key_digest(python, key_paths["untrusted_public"], output_dir / ".digest-other")
        if trusted_digest == untrusted_digest:
            raise PackageError("trusted and untrusted test keys are identical")
        verification = boot_manifest.get("custom_boot_verification")
        if not isinstance(verification, dict) or verification.get("public_key_digest") != trusted_digest:
            raise PackageError("bootloader trust root does not match the trusted signing key")
        for variant, manifest in app_manifests.items():
            if manifest.get("trusted_public_key_digest") != trusted_digest:
                raise PackageError(
                    f"{variant} runtime update trust root does not match the signing key"
                )

        package_bootloader = output_dir / "bootloader.bin"
        package_table = output_dir / "partition-table.bin"
        shutil.copy2(bootloader, package_bootloader)
        shutil.copy2(key_paths["trusted_public"], output_dir / "trusted-public-key.pem")
        subprocess.run(
            [
                str(espflash),
                "partition-table",
                "--to-binary",
                "--output",
                str(package_table),
                str(root / "partitions-ab.csv"),
            ],
            check=True,
        )
        if package_table.stat().st_size != 0xC00:
            raise PackageError("generated partition table must be exactly 0xC00 bytes")

        signed_images: dict[str, Path] = {}
        for variant, app_elf in app_elfs.items():
            unsigned = output_dir / f".{variant}-unsigned.bin"
            signed = output_dir / f"{variant}-signed.bin"
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
                    str(package_bootloader),
                    "--partition-table",
                    str(root / "partitions-ab.csv"),
                    "--partition-table-offset",
                    hex(TABLE_OFFSET),
                    "--target-app-partition",
                    "ota_0",
                    str(app_elf),
                    str(unsigned),
                ],
                check=True,
            )
            sign_image(python, trusted_signer, unsigned, signed)
            verify_image(python, key_paths["trusted_public"], signed, expect_valid=True)
            unsigned.unlink()
            if signed.stat().st_size > OTA_SIZE:
                raise PackageError(f"{variant} image exceeds an OTA slot")
            signed_prefix = signed.read_bytes()[:80]
            if (
                len(signed_prefix) != 80
                or int.from_bytes(signed_prefix[32:36], "little") != 0xABCD5432
                or int.from_bytes(signed_prefix[36:40], "little")
                != app_manifests[variant]["secure_version"]
                or signed_prefix[48:80].split(b"\0", 1)[0].decode(
                    "utf-8", errors="replace"
                )
                != app_manifests[variant]["image_version"]
            ):
                raise PackageError(f"{variant} image metadata differs from build evidence")
            signed_images[variant] = signed

        untrusted_unsigned = output_dir / ".untrusted-unsigned.bin"
        untrusted_signed = output_dir / "untrusted-signed.bin"
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
                str(package_bootloader),
                "--partition-table",
                str(root / "partitions-ab.csv"),
                "--partition-table-offset",
                hex(TABLE_OFFSET),
                "--target-app-partition",
                "ota_0",
                str(app_elfs["failure"]),
                str(untrusted_unsigned),
            ],
            check=True,
        )
        sign_image(python, key_paths["untrusted_private"], untrusted_unsigned, untrusted_signed)
        verify_image(python, key_paths["untrusted_public"], untrusted_signed, expect_valid=True)
        verify_image(python, key_paths["trusted_public"], untrusted_signed, expect_valid=False)
        untrusted_unsigned.unlink()

        for variant, manifest_path in app_paths.items():
            shutil.copy2(manifest_path, output_dir / f"{variant}-build.json")
        shutil.copy2(boot_path, output_dir / "bootloader-build.json")
        file_names = [
            "base-build.json",
            "base-signed.bin",
            "bootloader-build.json",
            "bootloader.bin",
            "failure-build.json",
            "failure-signed.bin",
            "partition-table.bin",
            "success-build.json",
            "success-signed.bin",
            "trusted-public-key.pem",
            "untrusted-signed.bin",
        ]
        files = {
            name: {
                "file": name,
                "sha256": sha256_file(output_dir / name),
                "size": (output_dir / name).stat().st_size,
            }
            for name in file_names
        }
        manifest = {
            "addresses": {
                "bootloader": BOOTLOADER_OFFSET,
                "ota_0": OTA_0_OFFSET,
                "ota_1": OTA_1_OFFSET,
                "otadata": 0xF000,
                "partition_table": TABLE_OFFSET,
            },
            "created_at": datetime.now(UTC).isoformat(),
            "device_preconditions": {
                "chip": "esp32s2",
                "flash_encryption": "disabled",
                "flash_size": 0x400000,
                "rom_download": "enabled",
                "secure_boot": "disabled",
            },
            "efuse_operations_performed": False,
            "files": files,
            "kind": "rissokey-signed-ab-package",
            "layout": {
                "fido_store_offset": FIDO_STORE_OFFSET,
                "fido_store_size": FIDO_STORE_SIZE,
                "ota_slot_size": OTA_SIZE,
                "partition_csv_sha256": sha256_file(root / "partitions-ab.csv"),
            },
            "private_key_included": False,
            "schema": 1,
            "security_profile": args.security_profile,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "tests": {
                "failure_image_confirms": False,
                "success_image_confirms_after_successful_ctap": True,
                "untrusted_image_signed_by_different_key": True,
            },
            "trusted_public_key_digest": trusted_digest,
            "usb_update": {
                "images": {
                    variant: {
                        **files[signed_images[variant].name],
                        "secure_version": app_manifests[variant]["secure_version"],
                        "version": app_manifests[variant]["image_version"],
                    }
                    for variant in ("base", "failure", "success")
                },
                "plaintext_signed_images": True,
                "target_selected_by_device": True,
            },
            "writes_fido_store": False,
        }
        manifest_path = output_dir / "rissokey-signed-ab-package.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (
        RuntimeError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"signed A/B package failed: {error}", file=sys.stderr)
        return 1

    print(f"prepared signed A/B device-test package at {output_dir}")
    print("private signing keys were not copied; nothing was flashed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
