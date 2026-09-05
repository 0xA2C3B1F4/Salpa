#!/usr/bin/env python3
"""Load and validate RissoKey board and security profiles."""

from __future__ import annotations

import json
from pathlib import Path


PROFILE_PATH = Path("policy/security-profiles.json")
SUPPORTED_MCUS = {"esp32s2", "esp32s3"}
REQUIRED_PROFILE_KEYS = {
    "artifact_recording_allowed",
    "blocking_conditions",
    "board",
    "cargo_features",
    "mcu",
    "release_eligible",
    "security",
    "status",
    "user_presence",
}
REQUIRED_SECURITY_KEYS = {
    "debug_access",
    "flash_encryption",
    "rom_download",
    "secure_boot",
}


class SecurityProfileError(RuntimeError):
    """A security profile is missing, inconsistent, or unsafe to use."""


def _string_list(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value), key=str.casefold)
    ):
        raise SecurityProfileError(f"{field} must be a sorted list of unique strings")
    return value


def load_security_profiles(root: Path) -> dict[str, dict[str, object]]:
    path = root / PROFILE_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SecurityProfileError(f"cannot read {PROFILE_PATH}: {error}") from error

    if not isinstance(document, dict) or document.get("schema") != 1:
        raise SecurityProfileError(f"unsupported {PROFILE_PATH} schema")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise SecurityProfileError(f"{PROFILE_PATH} must contain profiles")
    if list(profiles) != sorted(profiles, key=str.casefold):
        raise SecurityProfileError(f"{PROFILE_PATH} profile names must be sorted")

    for name, profile in profiles.items():
        if not isinstance(name, str) or not name:
            raise SecurityProfileError("profile names must be non-empty strings")
        if not isinstance(profile, dict) or set(profile) != REQUIRED_PROFILE_KEYS:
            raise SecurityProfileError(f"profile {name} has an unexpected field set")
        if profile["mcu"] not in SUPPORTED_MCUS:
            raise SecurityProfileError(f"profile {name} has an unsupported MCU")
        for field in ("board", "status"):
            if not isinstance(profile[field], str) or not profile[field]:
                raise SecurityProfileError(f"profile {name} has an invalid {field}")
        for field in ("artifact_recording_allowed", "release_eligible"):
            if not isinstance(profile[field], bool):
                raise SecurityProfileError(f"profile {name} has an invalid {field}")
        if profile["release_eligible"] and not profile["artifact_recording_allowed"]:
            raise SecurityProfileError(
                f"profile {name} cannot be release eligible while artifact recording is blocked"
            )

        feature_policy = profile["cargo_features"]
        if not isinstance(feature_policy, dict) or set(feature_policy) != {
            "forbidden",
            "required",
        }:
            raise SecurityProfileError(f"profile {name} has an invalid Cargo feature policy")
        required = _string_list(feature_policy["required"], f"{name}.cargo_features.required")
        forbidden = _string_list(
            feature_policy["forbidden"], f"{name}.cargo_features.forbidden"
        )
        if set(required) & set(forbidden):
            raise SecurityProfileError(f"profile {name} requires and forbids the same feature")

        security = profile["security"]
        if not isinstance(security, dict) or set(security) != REQUIRED_SECURITY_KEYS:
            raise SecurityProfileError(f"profile {name} has an invalid security field set")
        if any(not isinstance(value, str) or not value for value in security.values()):
            raise SecurityProfileError(f"profile {name} has an invalid security value")

        presence = profile["user_presence"]
        if not isinstance(presence, dict) or set(presence) != {
            "active_level",
            "boot_strapping_input",
            "gpio",
        }:
            raise SecurityProfileError(f"profile {name} has an invalid user-presence field set")
        if not isinstance(presence["boot_strapping_input"], bool):
            raise SecurityProfileError(f"profile {name} has an invalid boot-strapping flag")
        if presence["gpio"] is not None and (
            not isinstance(presence["gpio"], int) or presence["gpio"] < 0
        ):
            raise SecurityProfileError(f"profile {name} has an invalid user-presence GPIO")
        if presence["active_level"] not in {None, "high", "low"}:
            raise SecurityProfileError(f"profile {name} has an invalid active level")
        _string_list(profile["blocking_conditions"], f"{name}.blocking_conditions")

    return profiles


def select_candidate_profile(
    root: Path,
    name: str,
    mcu: str,
    expanded_features: set[str],
) -> dict[str, object]:
    profiles = load_security_profiles(root)
    try:
        profile = profiles[name]
    except KeyError as error:
        raise SecurityProfileError(f"unknown security profile: {name}") from error
    if profile["mcu"] != mcu:
        raise SecurityProfileError(
            f"security profile {name} targets {profile['mcu']}, not {mcu}"
        )

    feature_policy = profile["cargo_features"]
    required = set(feature_policy["required"])
    forbidden = set(feature_policy["forbidden"])
    missing = required - expanded_features
    selected_forbidden = forbidden & expanded_features
    if missing:
        raise SecurityProfileError(
            f"security profile {name} is missing features: {', '.join(sorted(missing))}"
        )
    if selected_forbidden:
        raise SecurityProfileError(
            f"security profile {name} enables forbidden features: "
            f"{', '.join(sorted(selected_forbidden))}"
        )
    if not profile["artifact_recording_allowed"]:
        raise SecurityProfileError(
            f"security profile {name} is not allowed to record firmware candidates"
        )
    return profile
