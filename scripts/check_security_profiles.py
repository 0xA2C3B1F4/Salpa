#!/usr/bin/env python3
"""Validate every machine-readable Salpa security profile."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from public_tree import repository_root
from security_profiles import SecurityProfileError, load_security_profiles


def validate_migration_profile(profiles: dict[str, dict[str, object]]) -> None:
    name = "wemos-s2-mini-e000-migration-test"
    try:
        profile = profiles[name]
    except KeyError as error:
        raise SecurityProfileError(f"required profile is missing: {name}") from error
    expected_security = {
        "debug_access": "enabled",
        "flash_encryption": "disabled",
        "rom_download": "enabled",
        "secure_boot": "disabled",
    }
    if profile["artifact_recording_allowed"] or profile["release_eligible"]:
        raise SecurityProfileError(f"{name} must not record or release firmware candidates")
    if profile["status"] != "device-test-passed":
        raise SecurityProfileError(f"{name} must record the completed device gate")
    if profile["security"] != expected_security:
        raise SecurityProfileError(f"{name} must keep every irreversible protection disabled")
    if profile["user_presence"] != {
        "active_level": "low",
        "boot_strapping_input": True,
        "gpio": 0,
    }:
        raise SecurityProfileError(f"{name} must retain the current GPIO0 risk declaration")


def validate_signed_ab_profile(profiles: dict[str, dict[str, object]]) -> None:
    name = "wemos-s2-mini-signed-ab-test"
    try:
        profile = profiles[name]
    except KeyError as error:
        raise SecurityProfileError(f"required profile is missing: {name}") from error
    if profile["artifact_recording_allowed"] or profile["release_eligible"]:
        raise SecurityProfileError(f"{name} must not record or release firmware candidates")
    if profile["status"] != "device-test-passed":
        raise SecurityProfileError(f"{name} must record the completed physical A/B gate")
    if profile["security"] != {
        "debug_access": "enabled",
        "flash_encryption": "disabled",
        "rom_download": "enabled",
        "secure_boot": "development-key-pinned-bootloader-without-efuse",
    }:
        raise SecurityProfileError(f"{name} must remain reversible and non-release")
    expected_blockers = {
        "Credential flash is not encrypted.",
        "GPIO0 is both user presence and a boot strapping input.",
        "Hardware Secure Boot V2 is not enforced.",
    }
    if set(profile["blocking_conditions"]) != expected_blockers:
        raise SecurityProfileError(f"{name} has stale or missing signed A/B blockers")
    required = profile["cargo_features"]["required"]
    if required != [
        "ctaphid-bringup",
        "fido-stack",
        "mcu-esp32s2",
        "signed-ab-update",
    ]:
        raise SecurityProfileError(f"{name} must require the signed A/B application path")
    if "release-flash-encryption" not in profile["cargo_features"]["forbidden"]:
        raise SecurityProfileError(f"{name} must reject the encrypted-storage feature")
    if profile["user_presence"] != {
        "active_level": "low",
        "boot_strapping_input": True,
        "gpio": 0,
    }:
        raise SecurityProfileError(f"{name} must retain the current GPIO0 risk declaration")


def validate_protected_profile(profiles: dict[str, dict[str, object]]) -> None:
    name = "wemos-s2-mini-protected-prototype"
    try:
        profile = profiles[name]
    except KeyError as error:
        raise SecurityProfileError(f"required profile is missing: {name}") from error
    if profile["artifact_recording_allowed"] or profile["release_eligible"]:
        raise SecurityProfileError(f"{name} must remain blocked from candidate recording")
    if profile["status"] != "prototype-accepted-release-blocked":
        raise SecurityProfileError(f"{name} must retain the accepted-prototype and blocked-release distinction")
    if profile["security"] != {
        "debug_access": "required-disabled",
        "flash_encryption": "required-release-mode",
        "rom_download": "must-use-approved-recovery-policy",
        "secure_boot": "required-v2-rsa",
    }:
        raise SecurityProfileError(f"{name} must retain the protected security contract")
    if profile["cargo_features"]["required"] != [
        "ctaphid-bringup",
        "fido-stack",
        "mcu-esp32s2",
        "non-strapping-user-presence",
        "release-flash-encryption",
        "signed-ab-update",
        "usb-signed-update",
    ]:
        raise SecurityProfileError(f"{name} must require encrypted signed A/B firmware")
    expected_blockers = {
        'Final ROM download policy has not been authorized or applied.',
        'Independent security review and physical attack evaluation remain incomplete.',
        'Production identity provisioning and support requirements remain incomplete.',
    }
    if set(profile["blocking_conditions"]) != expected_blockers:
        raise SecurityProfileError(f"{name} has stale or missing protection blockers")
    if profile["user_presence"] != {
        "active_level": "low",
        "boot_strapping_input": False,
        "gpio": 16,
    }:
        raise SecurityProfileError(f"{name} must bind user presence to active-low GPIO16")


def validate_non_strapping_profile(profiles: dict[str, dict[str, object]]) -> None:
    name = "wemos-s2-mini-non-strapping-up-test"
    try:
        profile = profiles[name]
    except KeyError as error:
        raise SecurityProfileError(f"required profile is missing: {name}") from error
    if profile["artifact_recording_allowed"] or profile["release_eligible"]:
        raise SecurityProfileError(f"{name} must remain a non-release device test")
    if profile["status"] != "device-test-passed":
        raise SecurityProfileError(f"{name} must record the completed GPIO16 physical gate")
    if profile["security"] != {
        "debug_access": "enabled",
        "flash_encryption": "disabled",
        "rom_download": "enabled",
        "secure_boot": "development-key-pinned-bootloader-without-efuse",
    }:
        raise SecurityProfileError(f"{name} must remain reversible and non-release")
    if profile["cargo_features"]["required"] != [
        "ctaphid-bringup",
        "fido-stack",
        "mcu-esp32s2",
        "non-strapping-user-presence",
        "signed-ab-update",
    ]:
        raise SecurityProfileError(f"{name} must require the GPIO16 signed A/B path")
    if profile["user_presence"] != {
        "active_level": "low",
        "boot_strapping_input": False,
        "gpio": 16,
    }:
        raise SecurityProfileError(f"{name} must bind user presence to active-low GPIO16")


def main() -> int:
    try:
        profiles = load_security_profiles(repository_root(__file__))
        validate_migration_profile(profiles)
        validate_signed_ab_profile(profiles)
        validate_non_strapping_profile(profiles)
        validate_protected_profile(profiles)
    except SecurityProfileError as error:
        print(f"security profile check failed: {error}", file=sys.stderr)
        return 1
    print(f"validated {len(profiles)} security profiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
