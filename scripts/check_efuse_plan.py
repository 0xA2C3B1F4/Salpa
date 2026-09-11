#!/usr/bin/env python3
"""Validate the ESP32-S2 eFuse plan and sanitized readback states."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from public_tree import repository_root


PLAN_PATH = Path("policy/esp32s2-protected-efuse-plan.json")
EXPECTED_STAGE_IDS = [
    "host-package",
    "flash-encryption",
    "ciphertext-install",
    "secure-boot-v2",
    "protected-acceptance",
    "rom-lockdown",
    "finalize",
]
EXPECTED_KEY_SLOTS = [
    {
        "block": "BLOCK_KEY0",
        "bytes": 32,
        "input": "unique-per-device-flash-encryption-key",
        "purpose": "XTS_AES_128_KEY",
        "read_protect": True,
        "secret": True,
        "write_protect": True,
    },
    {
        "block": "BLOCK_KEY1",
        "bytes": 32,
        "input": "rsa3072-secure-boot-public-key-digest",
        "purpose": "SECURE_BOOT_DIGEST0",
        "read_protect": False,
        "secret": False,
        "write_protect": True,
    },
]
EXPECTED_FLASH_FIELDS = {
    "DIS_BOOT_REMAP": 1,
    "DIS_DOWNLOAD_DCACHE": 1,
    "DIS_DOWNLOAD_ICACHE": 1,
    "DIS_DOWNLOAD_MANUAL_ENCRYPT": 1,
    "DIS_LEGACY_SPI_BOOT": 1,
    "HARD_DIS_JTAG": 1,
    "SOFT_DIS_JTAG": 1,
    "SPI_BOOT_CRYPT_CNT": 7,
}
EXPECTED_SECURE_BOOT_FIELDS = {
    "SECURE_BOOT_EN": 1,
    "SECURE_BOOT_KEY_REVOKE1": 1,
    "SECURE_BOOT_KEY_REVOKE2": 1,
}


class PlanError(RuntimeError):
    """The plan or readback does not meet the fail-closed contract."""


def load_json_object(path: Path, label: str) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    start = text.find("{")
    if start < 0:
        raise PlanError(f"{label} contains no JSON object")
    try:
        document = json.loads(text[start:])
    except json.JSONDecodeError as error:
        raise PlanError(f"{label} is not valid JSON: {error.msg}") from error
    if not isinstance(document, dict):
        raise PlanError(f"{label} must contain a JSON object")
    return document


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanError(message)


def operation(stage: dict[str, object], kind: str) -> dict[str, object]:
    operations = stage.get("operations")
    require(isinstance(operations, list), f"{stage.get('id')} has no operations")
    matches = [item for item in operations if isinstance(item, dict) and item.get("type") == kind]
    require(len(matches) == 1, f"{stage.get('id')} must have exactly one {kind} operation")
    return matches[0]


def validate_policy(plan: dict[str, object]) -> None:
    require(plan.get("schema") == 1, "unsupported eFuse plan schema")
    require(
        plan.get("kind") == "rissokey-esp32s2-protected-efuse-plan",
        "unexpected eFuse plan kind",
    )
    require(plan.get("status") == "draft-unapproved", "eFuse plan must remain unapproved")
    approval = plan.get("approval")
    require(isinstance(approval, dict), "eFuse plan has no approval contract")
    require(approval.get("approved") is False, "source must not grant eFuse approval")
    require(
        approval.get("required_immediately_before_each_irreversible_stage") is True,
        "every irreversible stage must require fresh authorization",
    )

    target = plan.get("target")
    require(isinstance(target, dict), "eFuse plan has no target")
    expected_target = {
        "board": "WEMOS S2 Mini",
        "chip": "esp32s2",
        "esp_idf_commit": "fff9895c82d744c7237be8847347bdd1b07c6643",
        "esp_idf_version": "6.1",
        "esptool_version": "5.4.0",
        "flash_bytes": 4194304,
        "flash_encryption": "AES-128-XTS-256-bit-key",
        "secure_boot": "v2-rsa3072",
    }
    require(target == expected_target, "eFuse plan target or pinned tools changed")
    require(plan.get("key_slots") == EXPECTED_KEY_SLOTS, "eFuse key-slot allocation changed")

    stages = plan.get("stages")
    require(isinstance(stages, list), "eFuse plan has no stages")
    require(
        [stage.get("id") for stage in stages if isinstance(stage, dict)] == EXPECTED_STAGE_IDS,
        "eFuse stages are missing or out of order",
    )
    require(all(isinstance(stage, dict) for stage in stages), "eFuse stage must be an object")
    by_id = {str(stage["id"]): stage for stage in stages}
    irreversible = {
        stage_id for stage_id, stage in by_id.items() if stage.get("irreversible") is True
    }
    require(
        irreversible == {"flash-encryption", "secure-boot-v2", "rom-lockdown"},
        "irreversible stage boundary changed",
    )
    for stage_id in irreversible:
        requirements = by_id[stage_id].get("requires")
        require(
            isinstance(requirements, list)
            and "explicit-immediate-user-authorization" in requirements,
            f"{stage_id} lacks immediate authorization",
        )

    flash_stage = by_id["flash-encryption"]
    flash_key = operation(flash_stage, "burn-key")
    require(
        flash_key == {
            "block": "BLOCK_KEY0",
            "purpose": "XTS_AES_128_KEY",
            "type": "burn-key",
        },
        "flash-encryption key operation changed",
    )
    require(
        operation(flash_stage, "burn-fields").get("fields") == EXPECTED_FLASH_FIELDS,
        "flash-encryption security fields changed",
    )
    require(
        operation(flash_stage, "write-protect-shared-security-group").get("field")
        == "DIS_ICACHE",
        "shared ESP32-S2 security write protection changed",
    )

    secure_boot_stage = by_id["secure-boot-v2"]
    secure_boot_key = operation(secure_boot_stage, "burn-key")
    require(
        secure_boot_key == {
            "block": "BLOCK_KEY1",
            "purpose": "SECURE_BOOT_DIGEST0",
            "type": "burn-key",
        },
        "Secure Boot digest operation changed",
    )
    require(
        operation(secure_boot_stage, "burn-fields").get("fields")
        == EXPECTED_SECURE_BOOT_FIELDS,
        "Secure Boot security fields changed",
    )
    require(
        operation(secure_boot_stage, "write-protect").get("field") == "RD_DIS",
        "RD_DIS must be write protected after the flash key is read protected",
    )
    lockdown = by_id["rom-lockdown"]
    require(lockdown.get("operations") == [],
            "final ROM operations must remain blocked pending the recovery design")
    require(lockdown.get("status") == "blocked-pending-recovery-and-anti-rollback-design",
            "final ROM stage must remain blocked")
    for gate in ("exact-chip-revision-and-current-identity-reverified",
                 "final-rom-policy-selected",
                 "both-valid-ota-slots-and-recovery-policy-tested-on-separate-device",
                 "anti-rollback-floor-and-shared-write-protection-reviewed",
                 "offline-backup-copy-restore-verified"):
        require(gate in lockdown["requires"], f"final ROM stage lacks {gate}")
    require(by_id["finalize"].get("requires") == [
        "selected-rom-policy-and-signed-usb-update-verified",
        "separate-flash-key-retention-decision",
        "no-secret-or-device-identifier-in-git-or-public-evidence",
    ], "finalization must not imply automatic key deletion")

    profiles = plan.get("readback_profiles")
    require(isinstance(profiles, dict), "eFuse plan has no readback profiles")
    require(
        set(profiles) == {"pristine", "provisioned_before_rom_lockdown"},
        "eFuse readback profile set changed",
    )
    for name, profile in profiles.items():
        require(isinstance(profile, dict) and profile, f"readback profile {name} is empty")
    pristine = profiles["pristine"]
    provisioned = profiles["provisioned_before_rom_lockdown"]
    require(
        pristine["SPI_BOOT_CRYPT_CNT"] == {"raw_value": "0x0", "writeable": True},
        "pristine flash-encryption counter changed",
    )
    require(
        provisioned["SPI_BOOT_CRYPT_CNT"] == {"raw_value": "0x7", "writeable": True},
        "release flash-encryption counter changed",
    )
    require(pristine["SECURE_BOOT_EN"]["value"] is False, "pristine Secure Boot must be disabled")
    require(
        provisioned["SECURE_BOOT_EN"]["value"] is True,
        "provisioned Secure Boot must be enabled",
    )
    require(
        provisioned["ENABLE_SECURITY_DOWNLOAD"]["value"] is False,
        "full readback must precede ROM lockdown",
    )
    require(
        provisioned["SECURE_BOOT_AGGRESSIVE_REVOKE"]["value"] is False,
        "prototype must not enable aggressive key revocation",
    )


def validate_readback(
    plan: dict[str, object],
    summary: dict[str, object],
    state: str,
    secure_boot_digest: bytes | None = None,
) -> None:
    profiles = plan["readback_profiles"]
    assert isinstance(profiles, dict)
    expected = profiles.get(state)
    if not isinstance(expected, dict):
        raise PlanError(f"unknown readback state: {state}")
    for field, contract in expected.items():
        record = summary.get(field)
        if not isinstance(record, dict):
            raise PlanError(f"readback is missing required field: {field}")
        assert isinstance(contract, dict)
        for property_name, expected_value in contract.items():
            if record.get(property_name) != expected_value:
                raise PlanError(f"readback mismatch: {field}.{property_name}")
    if state == "provisioned_before_rom_lockdown":
        if secure_boot_digest is None:
            raise PlanError("provisioned readback requires the expected Secure Boot digest")
        if len(secure_boot_digest) != 32:
            raise PlanError("Secure Boot digest must contain exactly 32 bytes")
        block = summary.get("BLOCK_KEY1")
        assert isinstance(block, dict)
        if block.get("raw_value") != "0x" + secure_boot_digest.hex():
            raise PlanError("readback mismatch: BLOCK_KEY1.raw_value")


def synthetic_summary(profile: dict[str, object]) -> dict[str, object]:
    return {
        field: dict(contract) if isinstance(contract, dict) else contract
        for field, contract in profile.items()
    }


def run_self_test(plan: dict[str, object]) -> None:
    for invalid_operation in (
        {"field": "ENABLE_SECURITY_DOWNLOAD", "type": "burn-field"},
        {"field": "DIS_DOWNLOAD_MODE", "type": "burn-field"},
        {"field": "DIS_DOWNLOAD_MODE", "type": "write-protect"},
    ):
        unsafe_plan = copy.deepcopy(plan)
        unsafe_plan["stages"][5]["operations"] = [invalid_operation]
        try:
            validate_policy(unsafe_plan)
        except PlanError:
            pass
        else:
            raise PlanError("self-test accepted a premature final ROM operation")

    profiles = plan["readback_profiles"]
    assert isinstance(profiles, dict)
    for state in ("pristine", "provisioned_before_rom_lockdown"):
        profile = profiles[state]
        assert isinstance(profile, dict)
        valid = synthetic_summary(profile)
        digest = None
        if state == "provisioned_before_rom_lockdown":
            digest = bytes(range(32))
            valid["BLOCK_KEY1"]["raw_value"] = "0x" + digest.hex()
        validate_readback(plan, valid, state, digest)

        missing = copy.deepcopy(valid)
        missing.pop(next(iter(profile)))
        try:
            validate_readback(plan, missing, state, digest)
        except PlanError:
            pass
        else:
            raise PlanError(f"self-test accepted missing {state} field")

    unsafe = synthetic_summary(profiles["pristine"])
    unsafe["SECURE_BOOT_EN"]["value"] = True
    try:
        validate_readback(plan, unsafe, "pristine")
    except PlanError:
        pass
    else:
        raise PlanError("self-test accepted an already secured target as pristine")

    occupied = synthetic_summary(profiles["pristine"])
    occupied["BLOCK_KEY0"]["raw_value"] = "0x01"
    try:
        validate_readback(plan, occupied, "pristine")
    except PlanError:
        pass
    else:
        raise PlanError("self-test accepted an occupied flash-key block")

    unlocked = synthetic_summary(profiles["provisioned_before_rom_lockdown"])
    unlocked["BLOCK_KEY1"]["raw_value"] = "0x" + bytes(range(32)).hex()
    unlocked["RD_DIS"]["writeable"] = True
    try:
        validate_readback(
            plan,
            unlocked,
            "provisioned_before_rom_lockdown",
            bytes(range(32)),
        )
    except PlanError:
        pass
    else:
        raise PlanError("self-test accepted writable RD_DIS after provisioning")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the non-executable ESP32-S2 eFuse plan or compare a read-only "
            "espefuse JSON summary with a named fail-closed state."
        )
    )
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument(
        "--secure-boot-digest",
        type=Path,
        help="expected 32-byte public Secure Boot digest for a provisioned readback",
    )
    parser.add_argument(
        "--state",
        choices=("pristine", "provisioned_before_rom_lockdown"),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    root = repository_root(__file__)
    plan_path = (args.plan or root / PLAN_PATH).expanduser().resolve()
    try:
        plan = load_json_object(plan_path, "eFuse plan")
        validate_policy(plan)
        if args.summary is not None:
            if args.state is None:
                raise PlanError("--summary requires --state")
            summary = load_json_object(args.summary.expanduser().resolve(), "eFuse summary")
            digest = None
            if args.secure_boot_digest is not None:
                digest = args.secure_boot_digest.expanduser().resolve().read_bytes()
            validate_readback(plan, summary, args.state, digest)
        elif args.state is not None:
            raise PlanError("--state requires --summary")
        elif args.secure_boot_digest is not None:
            raise PlanError("--secure-boot-digest requires --summary")
        if args.self_test:
            run_self_test(plan)
    except (OSError, PlanError) as error:
        print(f"eFuse plan check failed: {error}", file=sys.stderr)
        return 1

    print("validated unapproved ESP32-S2 eFuse plan")
    if args.summary is not None:
        print(f"read-only eFuse summary matches state: {args.state}")
    if args.self_test:
        print("eFuse plan fail-closed self-tests passed")
    print("no eFuse command was generated or executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
