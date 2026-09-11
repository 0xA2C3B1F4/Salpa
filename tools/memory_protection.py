"""Check protected S2 ELF layout and decode the fixed, read-only RKMP reply.

This module never opens a device or treats register readback as fault-test proof.
"""

from __future__ import annotations

import re
import struct
import subprocess
from pathlib import Path

from host_common import sha256_file


def expected_permissions(iram_end: int, data_start: int) -> tuple[int, ...]:
    if (
        not 0x40028000 <= iram_end < 0x40050000
        or iram_end % 4
        or data_start != iram_end - 0x70000
    ):
        raise ValueError("unsupported PMS SRAM layout")
    return (
        0x6DB,
        ((iram_end >> 2) & 0x1FFFF) | 0x60000,
        0,
        0x55 | (((data_start >> 2) & 0x1FFFF) << 8) | 0x1A000000,
        0x7800,
        0,
        0x1B000,
        0,
    )


def decode_status(reply: bytes, *, iram_end: int, data_start: int) -> dict:
    """Require the caller's ELF boundaries, not boundaries asserted by a device."""
    expected = expected_permissions(iram_end, data_start)
    if len(reply) != 64 or reply[:5] != b"RKMP\x01" or any(reply[48:]):
        raise ValueError("invalid PMS status format")
    boundaries = struct.unpack_from("<II", reply, 8)
    permissions = struct.unpack_from("<8I", reply, 16)
    if boundaries != (iram_end, data_start):
        raise ValueError("PMS status does not match the candidate layout")
    if reply[5:8] != b"\x0f\x0f\x00" or permissions != expected:
        raise ValueError("PMS permission, lock or monitor check failed")
    return {
        "schema": 1,
        "iram_end": iram_end,
        "data_start": data_start,
        "permissions": list(permissions),
        "all_banks_locked": True,
        "all_monitors_enabled": True,
        "fault_pending": False,
        "hardware_fault_enforcement_tested": False,
    }


def parse_sections(output: str) -> list[dict]:
    sections = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+", line)
        if match and index + 1 < len(lines):
            name, size, address = match.groups()
            sections.append({
                "name": name,
                "size": int(size, 16),
                "address": int(address, 16),
                "flags": set(lines[index + 1].strip().split(", ")),
            })
    if not sections:
        raise ValueError("no ELF sections found")
    return sections


def validate_layout(sections: list[dict], symbols: dict[str, int]) -> dict:
    try:
        iram_end = symbols["_salpa_pms_iram_end"]
        data_start = symbols["_data_start"]
        stack_low = symbols["_stack_end"]
        stack_high = symbols["_stack_start"]
    except KeyError:
        raise ValueError("missing protected S2 layout symbols") from None
    permissions = expected_permissions(iram_end, data_start)
    if not data_start <= stack_low < stack_high <= 0x40000000:
        raise ValueError("stack is outside writable SRAM")
    handlers = [address for name, address in symbols.items()
                if name.endswith("::__esp_hal_internal_memory_fault")]
    if len(handlers) != 1 or not 0x40020000 <= handlers[0] < iram_end:
        raise ValueError("PMS handler is not in protected IRAM")
    required = {".rwtext", ".vectors", ".data", ".stack"}
    for section in sections:
        if not section["size"] or "ALLOC" not in section["flags"]:
            continue
        required.discard(section["name"])
        start = section["address"]
        end = start + section["size"]
        if 0x40020000 <= start < 0x40070000:
            if end > iram_end or "READONLY" not in section["flags"]:
                raise ValueError("SRAM instruction alias has an incompatible section")
        if "CODE" in section["flags"]:
            if not (0x40020000 <= start < end <= iram_end
                    or 0x40080000 <= start < end <= 0x40400000):
                raise ValueError("executable section falls outside RX memory")
            if "READONLY" not in section["flags"]:
                raise ValueError("executable section is marked writable")
        if 0x3FFB0000 <= start < 0x40000000:
            reservation = section["name"] == ".salpa.pms.dram_alias_reservation"
            if reservation:
                if end != data_start or "CONTENTS" in section["flags"]:
                    raise ValueError("invalid SRAM alias reservation")
            elif not data_start <= start < end <= 0x40000000:
                raise ValueError("data section overlaps protected code")
    if required:
        raise ValueError("incomplete protected runtime layout")
    return {
        "schema": 1,
        "iram_end": iram_end,
        "data_start": data_start,
        "stack_reserved_bytes": stack_high - stack_low,
        "handler_address": handlers[0],
        "expected_permissions": list(permissions),
        "device_accessed": False,
    }


def check_elf(elf: Path) -> dict:
    elf = elf.resolve(strict=True)
    sections = subprocess.check_output(
        ["xtensa-esp32s2-elf-objdump", "-h", str(elf)], text=True
    )
    names = subprocess.check_output(
        ["xtensa-esp32s2-elf-nm", "-n", "-C", str(elf)], text=True
    )
    symbols = {}
    for line in names.splitlines():
        match = re.match(r"^([0-9a-f]+)\s+\S\s+(.+)$", line)
        if match:
            symbols[match[2]] = int(match[1], 16)
    result = validate_layout(parse_sections(sections), symbols)
    start = result["handler_address"]
    disassembly = subprocess.check_output(
        ["xtensa-esp32s2-elf-objdump", "-d", "-C",
         f"--start-address={start}", f"--stop-address={start + 128}", str(elf)],
        text=True,
    )
    validate_handler(disassembly, start)
    result["handler_has_no_calls_or_returns"] = True
    result["elf_sha256"] = sha256_file(elf)
    return result


def validate_handler(disassembly: str, start: int) -> None:
    """Keep the halt routine independent of flash and external dispatch calls."""
    match = re.search(
        rf"^{start:x} <[^\n]*::__esp_hal_internal_memory_fault>:\n(.*?)(?=^\w+ <|\Z)",
        disassembly, re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise ValueError("missing PMS handler disassembly")
    body = match[1]
    instructions = re.findall(
        r"^([0-9a-f]+):[ \t]+[0-9a-f]+[ \t]+(\S+)[ \t]*([^\n]*)",
        body, re.MULTILINE,
    )
    mnemonics = {mnemonic for _, mnemonic, _ in instructions}
    # A tiny fixed halt routine is intentional. New codegen needs review.
    allowed = {"entry", "movi.n", "movi", "xsr.intenable", "rsync", "j", "nop.n", "nop"}
    if not mnemonics <= allowed or not {"xsr.intenable", "rsync", "j"} <= mnemonics:
        raise ValueError("PMS halt routine has unexpected instructions")
    addresses = {int(address, 16) for address, _, _ in instructions}
    for _, mnemonic, operands in instructions:
        if mnemonic == "j":
            target = int(operands.split()[0], 16)
            if target not in addresses:
                raise ValueError("PMS halt routine branches outside IRAM handler")
