"""Explicit production Swift sources shared by installation and fixture builds."""

from pathlib import Path


SOURCE_NAMES = (
    "Support.swift", "Inventory.swift", "Keychain.swift", "UserApproval.swift",
    "Crypto.swift", "Attestation.swift", "Backup.swift", "AttestationRecovery.swift",
    "main.swift",
)


def production_sources() -> list[Path]:
    root = Path(__file__).resolve().parent
    return [root / name for name in SOURCE_NAMES]
