#!/usr/bin/env python3
"""Build the reversible ESP32-S2 signed A/B bootloader off-device."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import git_output, is_within, parse_sdkconfig, salpa_environment, sha256_file


PINNED_IDF_COMMIT = "fff9895c82d744c7237be8847347bdd1b07c6643"
EXPECTED_ESPTOOL_VERSION = "5.4.0"
PROJECT_PATH = Path("security/esp-idf-bootloader")
DEVELOPMENT_DEFAULTS_PATH = PROJECT_PATH / "sdkconfig.defaults.esp32s2-signed-ab-development"
PROTECTED_DEFAULTS_PATH = PROJECT_PATH / "sdkconfig.defaults.esp32s2-protected-external"
TABLE_OFFSET = 0xE000
BOOTLOADER_OFFSET = 0x1000


class BuildError(RuntimeError):
    """The signed A/B bootloader build gate was not met."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def idf_build_environment(idf_path: Path, idf_tools_path: Path) -> dict[str, str]:
    """Return the pinned ESP-IDF export environment for this Python runtime."""
    if not idf_tools_path.is_dir() or idf_tools_path.is_symlink():
        raise BuildError("--idf-tools-path must be an existing real directory")

    environment = salpa_environment(dict(os.environ))
    environment["IDF_TOOLS_PATH"] = str(idf_tools_path)
    result = subprocess.run(
        [
            sys.executable,
            str(idf_path / "tools/idf_tools.py"),
            "export",
            "--format",
            "key-value",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    exported: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {
            "ESP_IDF_VERSION",
            "ESP_ROM_ELF_DIR",
            "IDF_PYTHON_ENV_PATH",
            "OPENOCD_SCRIPTS",
            "PATH",
        }:
            exported[key] = value

    required = {"ESP_IDF_VERSION", "IDF_PYTHON_ENV_PATH", "PATH"}
    missing = sorted(required - exported.keys())
    if missing:
        raise BuildError(
            "ESP-IDF tool export omitted required variables: " + ", ".join(missing)
        )
    if exported["ESP_IDF_VERSION"] != "6.1":
        raise BuildError("ESP-IDF tool export did not report version 6.1")
    if Path(exported["IDF_PYTHON_ENV_PATH"]).resolve() != Path(sys.prefix).resolve():
        raise BuildError("run the builder with the pinned ESP-IDF Python environment")

    original_path = environment.get("PATH", "")
    exported_path = exported["PATH"]
    if exported_path.count("$PATH") != 1:
        raise BuildError("ESP-IDF tool export returned an unexpected PATH template")
    exported["PATH"] = exported_path.replace("$PATH", original_path)
    environment.update(exported)
    environment.update(
        {
            "IDF_PATH": str(idf_path),
            "SALPA_SIGNED_AB_BOOTLOADER": "1",
        }
    )
    compiler = shutil.which("xtensa-esp32s2-elf-gcc", path=environment["PATH"])
    if compiler is None or not is_within(Path(compiler).resolve(), idf_tools_path):
        raise BuildError("pinned ESP32-S2 compiler is unavailable under --idf-tools-path")
    return environment


def validate_sdkconfig(
    path: Path,
    key_digest: str,
    protected_external: bool,
    read_only_efuses: bool = False,
) -> None:
    values = parse_sdkconfig(path)
    required = {
        "CONFIG_IDF_TARGET": '"esp32s2"',
        "CONFIG_PARTITION_TABLE_OFFSET": "0xE000",
        "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE": "y",
        "CONFIG_ESP_CONSOLE_USB_CDC": "y",
        "CONFIG_RISSOKEY_SIGNED_AB_BOOTLOADER": "y",
        "CONFIG_RISSOKEY_UPDATE_KEY_DIGEST_HEX": f'"{key_digest}"',
        "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME": "y",
    }
    forbidden = {
        "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES",
        "CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT",
        "CONFIG_SECURE_DISABLE_ROM_DL_MODE",
        "CONFIG_ESP_CONSOLE_UART_DEFAULT",
    }
    if read_only_efuses:
        if not protected_external:
            raise BuildError("read-only eFuse enforcement requires --protected-external")
        required.update(
            {
                "CONFIG_RISSOKEY_EFUSE_READ_ONLY": "y",
                "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK": "y",
                "CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD": "16",
            }
        )
        forbidden.update(
            {
                "CONFIG_EFUSE_VIRTUAL",
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP",
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_ON_POWER_ON",
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS",
            }
        )
    else:
        forbidden.update(
            {"CONFIG_RISSOKEY_EFUSE_READ_ONLY", "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK"}
        )
    if protected_external:
        required.update(
            {
                "CONFIG_SECURE_BOOT": "y",
                "CONFIG_SECURE_BOOT_V2_ENABLED": "y",
                "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE": "y",
                "CONFIG_SECURE_FLASH_ENC_ENABLED": "y",
                "CONFIG_SECURE_FLASH_ENCRYPTION_AES128": "y",
                "CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE_EFUSES": "y",
                "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE": "y",
            }
        )
        forbidden.update(
            {
                "CONFIG_SECURE_BOOT_ALLOW_JTAG",
                "CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE",
                "CONFIG_SECURE_BOOT_INSECURE",
                "CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS",
                "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT",
                "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE",
                "CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT",
            }
        )
    else:
        required.update(
            {
                "CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT": "y",
                "CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT": "y",
            }
        )
        forbidden.update(
            {
                "CONFIG_SECURE_BOOT",
                "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE",
                "CONFIG_SECURE_FLASH_ENC_ENABLED",
            }
        )
    for key, expected in required.items():
        if values.get(key) != expected:
            raise BuildError(f"generated sdkconfig does not set {key}={expected}")
    enabled = sorted(key for key in forbidden if values.get(key) == "y")
    if enabled:
        raise BuildError(f"generated sdkconfig enables forbidden options: {', '.join(enabled)}")


def validate_linked_efuse_policy(elf: Path, environment: dict[str, str]) -> None:
    """Check the linked target, not only the requested Kconfig settings."""
    nm = shutil.which("xtensa-esp32s2-elf-nm", path=environment["PATH"])
    if nm is None:
        raise BuildError("pinned ESP32-S2 symbol inspection tool is unavailable")
    result = subprocess.run(
        [nm, "--defined-only", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    symbols = {line.split()[-1] for line in result.stdout.splitlines() if line.split()}
    required = {
        "__wrap_esp_efuse_update_secure_version",
        "__wrap_esp_efuse_utility_burn_chip_opt",
        "esp_efuse_check_secure_version",
        "esp_efuse_read_secure_version",
    }
    forbidden = {
        "esp_efuse_update_secure_version",
        "esp_efuse_utility_burn_chip_opt",
        "efuse_hal_program",
    }
    if not required <= symbols or forbidden & symbols:
        raise BuildError("linked bootloader does not enforce the read-only eFuse policy")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a public-key-pinned signed A/B bootloader without flashing "
            "hardware or changing eFuses."
        )
    )
    parser.add_argument("--idf-path", required=True, type=Path)
    parser.add_argument(
        "--idf-tools-path",
        required=True,
        type=Path,
        help="external IDF_TOOLS_PATH containing the pinned ESP32-S2 compiler",
    )
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument(
        "--protected-external",
        action="store_true",
        help=(
            "build the hazardous external-provisioning Secure Boot and release "
            "flash-encryption configuration; still performs no device action"
        ),
    )
    parser.add_argument(
        "--read-only-efuses",
        action="store_true",
        help=(
            "for an already provisioned device: enforce its 16-bit hardware "
            "version floor and remove eFuse programming from the bootloader"
        ),
    )
    args = parser.parse_args()

    root = repository_root()
    idf_path = args.idf_path.expanduser().resolve()
    idf_tools_path = args.idf_tools_path.expanduser().resolve()
    public_key = args.public_key.expanduser().resolve()
    build_dir = args.build_dir.expanduser().resolve()
    project_dir = root / PROJECT_PATH

    try:
        if args.read_only_efuses and not args.protected_external:
            raise BuildError("--read-only-efuses requires --protected-external")
        if is_within(build_dir, root) or is_within(public_key, root):
            raise BuildError("build directory and public key must stay outside Git")
        if build_dir.exists() and any(build_dir.iterdir()):
            raise BuildError("build directory must be new or empty")
        if not public_key.is_file() or public_key.is_symlink():
            raise BuildError("public key must be an existing regular file")
        key_data = public_key.read_bytes()
        if b"PRIVATE KEY" in key_data or b"PUBLIC KEY" not in key_data:
            raise BuildError("--public-key must contain only a PEM public key")
        if not (idf_path / "tools/idf.py").is_file():
            raise BuildError("--idf-path is not an ESP-IDF checkout")
        idf_commit = git_output(idf_path, "rev-parse", "HEAD")
        if idf_commit != PINNED_IDF_COMMIT:
            raise BuildError(
                f"ESP-IDF must be pinned to {PINNED_IDF_COMMIT}; found {idf_commit}"
            )
        if importlib.metadata.version("esptool") != EXPECTED_ESPTOOL_VERSION:
            raise BuildError(f"esptool must be exactly {EXPECTED_ESPTOOL_VERSION}")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("source tree must be clean before recording build evidence")

        build_dir.mkdir(parents=True, exist_ok=True)
        digest_path = build_dir / "trusted-key-digest.bin"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "espsecure",
                "digest-rsa-public-key",
                "--keyfile",
                str(public_key),
                "--output",
                str(digest_path),
            ],
            check=True,
        )
        digest = digest_path.read_bytes()
        if len(digest) != 32:
            raise BuildError("espsecure produced an unexpected public-key digest size")
        key_digest = digest.hex()
        if re.fullmatch(r"[0-9a-f]{64}", key_digest) is None:
            raise BuildError("public-key digest is malformed")

        source_defaults = (
            PROTECTED_DEFAULTS_PATH
            if args.protected_external
            else DEVELOPMENT_DEFAULTS_PATH
        )
        defaults = build_dir / "sdkconfig.defaults"
        defaults.write_text(
            (root / source_defaults).read_text(encoding="utf-8")
            + f'\nCONFIG_RISSOKEY_UPDATE_KEY_DIGEST_HEX="{key_digest}"\n'
            + (
                "CONFIG_RISSOKEY_EFUSE_READ_ONLY=y\n"
                "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y\n"
                "CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD=16\n"
                if args.read_only_efuses
                else ""
            ),
            encoding="utf-8",
        )
        sdkconfig = build_dir / "sdkconfig"
        environment = idf_build_environment(idf_path, idf_tools_path)
        command = [
            sys.executable,
            str(idf_path / "tools/idf.py"),
            "-B",
            str(build_dir),
            "-D",
            "IDF_TARGET=esp32s2",
            "-D",
            f"SDKCONFIG={sdkconfig}",
            "-D",
            f"SDKCONFIG_DEFAULTS={defaults}",
            "bootloader",
        ]
        subprocess.run(command, cwd=project_dir, env=environment, check=True)
        validate_sdkconfig(
            sdkconfig, key_digest, args.protected_external, args.read_only_efuses
        )

        bootloader_bin = build_dir / "bootloader/bootloader.bin"
        bootloader_elf = build_dir / "bootloader/bootloader.elf"
        for artifact in (bootloader_bin, bootloader_elf):
            if not artifact.is_file() or artifact.is_symlink():
                raise BuildError(f"missing regular build artifact: {artifact.name}")
        if bootloader_bin.stat().st_size > TABLE_OFFSET - BOOTLOADER_OFFSET:
            raise BuildError("bootloader does not fit before the 0xE000 partition table")
        if b"signature verification failed" not in bootloader_bin.read_bytes():
            raise BuildError("bootloader artifact lacks the custom signature rejection path")
        if args.read_only_efuses:
            validate_linked_efuse_policy(bootloader_elf, environment)
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise BuildError("bootloader build modified the source tree")

        manifest_kind = (
            "rissokey-protected-bootloader"
            if args.protected_external
            else "rissokey-signed-ab-bootloader"
        )
        security_profile = (
            "wemos-s2-mini-protected-prototype"
            if args.protected_external
            else "wemos-s2-mini-signed-ab-test"
        )
        partition_table = (
            root / "partitions-ab-encrypted.csv"
            if args.protected_external
            else root / "partitions-ab.csv"
        )
        manifest = {
            "artifacts": {
                "bootloader_bin": {
                    "file": "bootloader/bootloader.bin",
                    "sha256": sha256_file(bootloader_bin),
                    "size": bootloader_bin.stat().st_size,
                },
                "bootloader_elf": {
                    "file": "bootloader/bootloader.elf",
                    "sha256": sha256_file(bootloader_elf),
                    "size": bootloader_elf.stat().st_size,
                },
            },
            "build_only": True,
            "custom_boot_verification": {
                "algorithm": "RSA-3072-PSS-SHA256",
                "physical_flash_replacement_protected": False,
                "public_key_digest": key_digest,
                "verifies_every_app_slot": True,
                "hardware_secure_version_floor": args.read_only_efuses,
                "secure_version_field_bits": 16 if args.read_only_efuses else None,
                "automatic_efuse_programming_blocked": args.read_only_efuses,
            },
            "efuse_operations_performed": False,
            "esp_idf_commit": idf_commit,
            "flash_authorized": False,
            "generated_at": datetime.now(UTC).isoformat(),
            "kind": manifest_kind,
            "layout": {
                "bootloader_offset": BOOTLOADER_OFFSET,
                "partition_table_offset": TABLE_OFFSET,
                "partition_table_sha256": sha256_file(partition_table),
            },
            "protection": {
                "external_efuse_plan_required": args.protected_external,
                "flash_encryption": "release" if args.protected_external else "disabled",
                "secure_boot": "v2-rsa3072" if args.protected_external else "disabled",
            },
            "schema": 1,
            "sdkconfig_sha256": sha256_file(sdkconfig),
            "security_profile": security_profile,
            "source_commit": git_output(root, "rev-parse", "HEAD"),
            "source_tree": git_output(root, "rev-parse", "HEAD^{tree}"),
            "warning": (
                "Read-only eFuse profile for an already provisioned device. "
                "Build evidence does not authorize flashing or prove device behavior."
                if args.read_only_efuses
                else "Booting this protected configuration before completing the "
                "approved external plan can irreversibly program eFuses."
                if args.protected_external
                else "Development trust anchor only: eFuse Secure Boot and flash "
                "encryption remain disabled."
            ),
        }
        manifest_path = build_dir / (
            "rissokey-protected-bootloader-build.json"
            if args.protected_external
            else "rissokey-signed-ab-bootloader-build.json"
        )
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (
        BuildError,
        ValueError,
        OSError,
        subprocess.CalledProcessError,
        importlib.metadata.PackageNotFoundError,
    ) as error:
        print(f"signed A/B bootloader build failed: {error}", file=sys.stderr)
        return 1

    profile = "protected external" if args.protected_external else "signed A/B development"
    print(f"built {profile} bootloader at {bootloader_bin}")
    print(f"recorded host-only build evidence at {manifest_path}")
    print("nothing was flashed and no eFuse operation was performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
