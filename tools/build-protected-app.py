#!/usr/bin/env python3
"""Build a protected ESP32-S2 runtime or storage provisioner off-device."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import git_output, is_within, sha256_file


TARGET = "xtensa-esp32s2-none-elf"
FEATURES = {
    "runtime": [
        "ctaphid-bringup",
        "fido-stack",
        "mcu-esp32s2",
        "non-strapping-user-presence",
        "release-flash-encryption",
        "signed-ab-update",
        "usb-signed-update",
    ],
    "storage-provisioner": [
        "mcu-esp32s2",
        "non-strapping-user-presence",
        "release-flash-encryption",
        "storage-provisioning",
    ],
    "attestation-importer": [
        "attestation-import", "mcu-esp32s2", "non-strapping-user-presence", "release-flash-encryption",
    ],
}
RUNTIME_VARIANTS = {
    "normal": {"feature": None, "version": None},
    "rollback-failure": {
        "feature": "signed-ab-failure-test",
        "version": "0.1.1-ab-fail",
    },
}
BINARIES = {
    "runtime": "rissokey",
    "storage-provisioner": "provision-storage",
    "attestation-importer": "import-attestation",
}
REQUIRED_ENVIRONMENT = {
    "runtime": ["RISSO_KEY_USB_PID", "RISSO_KEY_USB_SERIAL", "RISSO_KEY_USB_VID"],
    "storage-provisioner": ["RISSO_KEY_PROVISIONING_ACK"],
    "attestation-importer": ["RISSO_KEY_ATTESTATION_IMPORT_ACK", "RISSO_KEY_ATTESTATION_CERT_SHA256_FILE", "RISSO_KEY_ATTESTATION_PUBLIC_FILE"],
}
EXACT_ENVIRONMENT = {
    "RISSO_KEY_PROVISIONING_ACK": "ERASE_FIDO_STORE",
    "RISSO_KEY_ATTESTATION_IMPORT_ACK": "INSTALL_ATTESTATION",
}


class BuildError(RuntimeError):
    """The protected application build gate was not met."""


def selected_features(image: str, runtime_variant: str) -> list[str]:
    features = FEATURES[image].copy()
    if image != "runtime":
        if runtime_variant != "normal":
            raise BuildError("--runtime-variant is only valid for the protected runtime")
        return features
    feature = RUNTIME_VARIANTS[runtime_variant]["feature"]
    if feature is not None:
        features.append(str(feature))
    return features


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def command_output(path: Path, *args: str) -> str:
    return subprocess.run(
        list(args), cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a release-flash-encryption ESP32-S2 image without packaging, "
            "flashing, or changing eFuses."
        )
    )
    parser.add_argument("--image", choices=sorted(FEATURES), required=True)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--update-key-digest")
    parser.add_argument("--secure-version", type=int)
    parser.add_argument(
        "--runtime-variant", choices=sorted(RUNTIME_VARIANTS), default="normal"
    )
    args = parser.parse_args()

    root = repository_root()
    build_dir = args.build_dir.expanduser().resolve()
    binary = BINARIES[args.image]
    runtime_variant = args.runtime_variant
    features = selected_features(args.image, runtime_variant)
    required_environment = REQUIRED_ENVIRONMENT[args.image]
    update_key_digest = args.update_key_digest
    secure_version = args.secure_version

    try:
        if is_within(build_dir, root):
            raise BuildError("build directory must stay outside the source repository")
        if build_dir.exists() and any(build_dir.iterdir()):
            raise BuildError("build directory must be new or empty")
        missing = [name for name in required_environment if not os.environ.get(name)]
        if missing:
            raise BuildError(f"missing required environment: {', '.join(missing)}")
        invalid = [
            name
            for name, expected in EXACT_ENVIRONMENT.items()
            if name in required_environment and os.environ.get(name) != expected
        ]
        if invalid:
            raise BuildError(
                "invalid explicit environment acknowledgement: " + ", ".join(invalid)
            )
        public_bindings = {}
        if args.image == "attestation-importer":
            for variable, size in [("RISSO_KEY_ATTESTATION_CERT_SHA256_FILE", 32), ("RISSO_KEY_ATTESTATION_PUBLIC_FILE", 65)]:
                path = Path(os.environ[variable])
                if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
                    raise BuildError("invalid public attestation binding file")
                public_bindings[variable] = sha256_file(path)
        if args.image == "runtime" and (
            update_key_digest is None
            or re.fullmatch(r"[0-9a-f]{64}", update_key_digest) is None
        ):
            raise BuildError(
                "protected runtime requires --update-key-digest with 64 lowercase hexadecimal characters"
            )
        if args.image != "runtime" and update_key_digest is not None:
            raise BuildError("--update-key-digest is only valid for the protected runtime")
        if args.image == "runtime" and (
            secure_version is None or not 0 <= secure_version <= 0xFFFF_FFFF
        ):
            raise BuildError(
                "protected runtime requires --secure-version as an unsigned 32-bit integer"
            )
        if args.image != "runtime" and secure_version is not None:
            raise BuildError("--secure-version is only valid for the protected runtime")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("source tree must be clean before recording build evidence")

        build_dir.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "CARGO_TARGET_DIR": str(build_dir),
                "RISSO_KEY_MCU": "esp32s2",
                "RISSO_KEY_PARTITION_PROFILE": "signed-ab-encrypted",
                "ESP_BOOTLOADER_ESP_IDF_CONFIG_SECURE_VERSION": str(
                    secure_version if secure_version is not None else 0
                ),
            }
        )
        if update_key_digest is not None:
            environment["RISSO_KEY_UPDATE_KEY_DIGEST_HEX"] = update_key_digest
        command = [
            str(root / "tools/cargo-esp"),
            "build",
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            ",".join(features),
            "--bin",
            binary,
        ]
        subprocess.run(command, cwd=root, env=environment, check=True)
        artifact = build_dir / TARGET / "release" / binary
        if not artifact.is_file() or artifact.is_symlink():
            raise BuildError("missing regular protected application ELF")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("application build modified the source tree")

        manifest = {
            "artifact": {
                "file": f"{TARGET}/release/{binary}",
                "sha256": sha256_file(artifact),
                "size": artifact.stat().st_size,
            },
            "build": {
                "binary": binary,
                "command": ["./tools/cargo-esp", *command[1:]],
                "environment_values_recorded": False,
                "features": features,
                "mcu": "esp32s2",
                "partition_profile": "signed-ab-encrypted",
                "required_environment": required_environment,
                "security_profile": "wemos-s2-mini-protected-prototype",
            },
            "build_only": True,
            "attestation": {
                "material_included": False,
                "installs_identity": args.image == "attestation-importer",
                "existing_identity_required_for_fido": True,
                "storage_only_initialization": args.image == "storage-provisioner",
                "private_key_embedded": False,
                "public_binding_files_sha256": public_bindings,
            },
            "efuse_operations_performed": False,
            "flash_authorized": False,
            "generated_at": datetime.now(UTC).isoformat(),
            "image": args.image,
            "image_version": (
                RUNTIME_VARIANTS[runtime_variant]["version"]
                if args.image == "runtime"
                else None
            ),
            "kind": "rissokey-protected-application",
            "runtime_variant": runtime_variant if args.image == "runtime" else None,
            "schema": 1,
            "secure_version": secure_version if secure_version is not None else 0,
            "trusted_public_key_digest": update_key_digest,
            "source": {
                "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
                "commit": git_output(root, "rev-parse", "HEAD"),
                "efuse_plan_sha256": sha256_file(
                    root / "policy/esp32s2-protected-efuse-plan.json"
                ),
                "partition_table_sha256": sha256_file(
                    root / "partitions-ab-encrypted.csv"
                ),
                "security_profiles_sha256": sha256_file(
                    root / "policy/security-profiles.json"
                ),
                "tree": git_output(root, "rev-parse", "HEAD^{tree}"),
            },
            "toolchain": {
                "cargo": command_output(root, "cargo", "-vV"),
                "rustc": command_output(root, "rustc", "-vV"),
            },
            "warning": (
                "Build-only protected image; never boot before the approved "
                "external eFuse sequence."
            ),
        }
        manifest_path = build_dir / f"rissokey-protected-{args.image}-build.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"protected application build failed: {error}", file=sys.stderr)
        return 1

    print(f"built protected {args.image} at {artifact}")
    print(f"recorded host-only build evidence at {manifest_path}")
    print("USB identity values were not recorded; nothing was flashed")
    if args.image == "storage-provisioner":
        print("Storage initialization erases attestation; verify the original backup before use and restore it before FIDO acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
