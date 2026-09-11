#!/usr/bin/env python3
"""Validate legacy, migration, signed A/B, and encrypted A/B flash layouts."""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True

from public_tree import repository_root


FLASH_SIZE = 0x400000
SECTOR_SIZE = 0x1000
TABLE_SIZE = 0x1000


class LayoutError(RuntimeError):
    """A partition layout is malformed or overlaps reserved flash."""


@dataclass(frozen=True)
class Partition:
    name: str
    kind: str
    subtype: str
    offset: int
    size: int
    flags: tuple[str, ...]

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class Layout:
    path: str
    table_offset: int
    partitions: tuple[Partition, ...]


def parse_number(raw: str, field: str) -> int:
    try:
        value = int(raw, 0)
    except ValueError as error:
        raise LayoutError(f"invalid {field}: {raw!r}") from error
    if value <= 0 or value % SECTOR_SIZE:
        raise LayoutError(f"{field} must be a positive 4 KiB multiple: {raw!r}")
    return value


def load_layout(root: Path, relative: str, table_offset: int) -> Layout:
    rows: list[Partition] = []
    try:
        lines = (root / relative).read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LayoutError(f"cannot read {relative}: {error}") from error

    for line_number, fields in enumerate(csv.reader(lines), start=1):
        if not fields or not fields[0].strip() or fields[0].lstrip().startswith("#"):
            continue
        if len(fields) not in {5, 6}:
            raise LayoutError(f"{relative}:{line_number} must have five or six fields")
        name, kind, subtype, raw_offset, raw_size = (item.strip() for item in fields[:5])
        flags = tuple(
            item.strip()
            for item in (fields[5].split(":") if len(fields) > 5 else [])
            if item.strip()
        )
        if len(flags) != len(set(flags)) or any(
            flag not in {"encrypted", "readonly"} for flag in flags
        ):
            raise LayoutError(f"{relative}:{line_number} has invalid flags")
        if not name or not kind or not subtype:
            raise LayoutError(f"{relative}:{line_number} has an empty identity field")
        rows.append(
            Partition(
                name=name,
                kind=kind,
                subtype=subtype,
                offset=parse_number(raw_offset, f"{relative}:{line_number} offset"),
                size=parse_number(raw_size, f"{relative}:{line_number} size"),
                flags=flags,
            )
        )
    if not rows:
        raise LayoutError(f"{relative} has no partitions")
    return Layout(relative, table_offset, tuple(rows))


def validate_layout(layout: Layout) -> None:
    names = [partition.name for partition in layout.partitions]
    if len(names) != len(set(names)):
        raise LayoutError(f"{layout.path} contains duplicate partition names")
    if layout.table_offset % SECTOR_SIZE:
        raise LayoutError(f"{layout.path} table offset is not sector aligned")

    regions = [(layout.table_offset, layout.table_offset + TABLE_SIZE, "partition table")]
    for partition in layout.partitions:
        if partition.end > FLASH_SIZE:
            raise LayoutError(f"{layout.path} partition exceeds 4 MiB: {partition.name}")
        regions.append((partition.offset, partition.end, partition.name))
    regions.sort()
    for previous, current in zip(regions, regions[1:]):
        if previous[1] > current[0]:
            raise LayoutError(
                f"{layout.path} overlaps {previous[2]} with {current[2]}"
            )


def by_name(layout: Layout) -> dict[str, Partition]:
    return {partition.name: partition for partition in layout.partitions}


def same_geometry(left: Partition, right: Partition) -> bool:
    return (
        left.name,
        left.kind,
        left.subtype,
        left.offset,
        left.size,
    ) == (
        right.name,
        right.kind,
        right.subtype,
        right.offset,
        right.size,
    )


def validate_contract(root: Path) -> tuple[Layout, Layout, Layout, Layout]:
    legacy = load_layout(root, "partitions.csv", 0x8000)
    migration = load_layout(root, "partitions-e000.csv", 0xE000)
    signed_ab = load_layout(root, "partitions-ab.csv", 0xE000)
    encrypted_ab = load_layout(root, "partitions-ab-encrypted.csv", 0xE000)
    validate_layout(legacy)
    validate_layout(migration)
    validate_layout(signed_ab)
    validate_layout(encrypted_ab)
    for layout in (legacy, migration, signed_ab):
        if any(partition.flags for partition in layout.partitions):
            raise LayoutError(f"{layout.path} must not enable partition flags")

    expected_names = {"factory", "fido_store", "nvs", "phy_init"}
    for layout in (legacy, migration):
        if set(by_name(layout)) != expected_names:
            raise LayoutError(f"{layout.path} must contain exactly {sorted(expected_names)}")

    old = by_name(legacy)
    new = by_name(migration)
    if (new["factory"].offset, new["factory"].size) != (0x10000, 0x3C0000):
        raise LayoutError("migration factory partition must be 0x10000+0x3C0000")
    if (new["nvs"].offset, new["nvs"].size) != (0x3D0000, 0x6000):
        raise LayoutError("migration NVS partition must be 0x3D0000+0x6000")
    if (new["phy_init"].offset, new["phy_init"].size) != (0x3D6000, 0x1000):
        raise LayoutError("migration PHY partition must be 0x3D6000+0x1000")
    if not same_geometry(new["fido_store"], old["fido_store"]):
        raise LayoutError("migration must preserve the exact fido_store partition")

    ab = by_name(signed_ab)
    expected_ab_names = {"fido_store", "nvs", "ota_0", "ota_1", "otadata", "phy_init"}
    if set(ab) != expected_ab_names:
        raise LayoutError(
            f"{signed_ab.path} must contain exactly {sorted(expected_ab_names)}"
        )
    expected_ab = {
        "otadata": ("data", "ota", 0xF000, 0x2000),
        "nvs": ("data", "nvs", 0x11000, 0x6000),
        "phy_init": ("data", "phy", 0x17000, 0x1000),
        "ota_0": ("app", "ota_0", 0x20000, 0x1E0000),
        "ota_1": ("app", "ota_1", 0x200000, 0x1E0000),
    }
    for name, (kind, subtype, offset, size) in expected_ab.items():
        partition = ab[name]
        if (
            partition.kind,
            partition.subtype,
            partition.offset,
            partition.size,
        ) != (kind, subtype, offset, size):
            raise LayoutError(f"signed A/B partition has an unexpected contract: {name}")
    if not same_geometry(ab["fido_store"], old["fido_store"]):
        raise LayoutError("signed A/B layout must preserve the exact fido_store partition")

    encrypted = by_name(encrypted_ab)
    if set(encrypted) != expected_ab_names:
        raise LayoutError(
            f"{encrypted_ab.path} must contain exactly {sorted(expected_ab_names)}"
        )
    for name, partition in ab.items():
        if not same_geometry(encrypted[name], partition):
            raise LayoutError(f"encrypted A/B layout changes partition geometry: {name}")
    expected_encrypted = {"otadata", "ota_0", "ota_1", "fido_store"}
    actual_encrypted = {
        name for name, partition in encrypted.items() if "encrypted" in partition.flags
    }
    if actual_encrypted != expected_encrypted:
        raise LayoutError(
            "encrypted A/B layout must flag otadata, both app slots, and fido_store"
        )
    unexpected_flags = [
        name
        for name, partition in encrypted.items()
        if name not in expected_encrypted and partition.flags
    ]
    if unexpected_flags:
        raise LayoutError("encrypted A/B layout has unexpected partition flags")
    return legacy, migration, signed_ab, encrypted_ab


def main() -> int:
    try:
        legacy, migration, signed_ab, encrypted_ab = validate_contract(repository_root(__file__))
    except LayoutError as error:
        print(f"partition layout check failed: {error}", file=sys.stderr)
        return 1
    print(
        f"validated {legacy.path} at 0x{legacy.table_offset:x} and "
        f"{migration.path}, {signed_ab.path}, plus {encrypted_ab.path} at "
        f"0x{migration.table_offset:x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
