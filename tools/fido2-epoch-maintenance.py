#!/usr/bin/env python3
"""Inspect or rehearse a fixed counter plan; programming needs a fresh approval file."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import stat
import struct
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import salpa_environment
from fido2_transport import open_connection

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "epoch_preview", Path(__file__).with_name("fido2-epoch-preview.py")
)
PREVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREVIEW)
COMMANDS = {"inspect": 0x13, "program": 0x14, "rehearse": 0x15}


class MaintenanceError(RuntimeError):
    pass


class DeviceMaintenanceError(MaintenanceError):
    def __init__(self, status: int, transaction_status: int | None = None):
        super().__init__("device rejected maintenance request")
        self.status = status
        self.transaction_status = transaction_status


def decode_plan(data: bytes) -> dict:
    if len(data) != 164 or data[:8] != b"RKMPLAN1" or data[163] != 0:
        raise MaintenanceError("invalid private maintenance plan")
    block0 = struct.unpack_from("<6I", data, 104)
    raw = (block0[4] >> 11) & 0xFFFF
    target = data[160]
    if not raw.bit_count() < target <= 16 or block0[0] & (1 << 18):
        raise MaintenanceError("counter is exhausted, unchanged or write protected")
    return {
        "plan_sha256": hashlib.sha256(data).hexdigest(),
        "target_epoch": target,
        "before_raw": raw,
        "fallback_sha256": data[128:160].hex(),
    }


def decode_response(data: bytes, plan: dict, command: int) -> dict:
    if len(data) != 64 or data[:4] != b"RKM1":
        raise MaintenanceError("device did not complete the maintenance operation")
    if data[4] != 0:
        detail = data[5] if data[4] == 6 and data[5] != 0 else None
        raise DeviceMaintenanceError(data[4], detail)
    sequences = list(struct.unpack_from("<II", data, 40))
    clock, raw, delta = struct.unpack_from("<IHH", data, 48)
    if (
        data[5] != plan["target_epoch"] or data[6] > 1
        or data[7] != raw.bit_count() or raw != plan["before_raw"]
        or data[8:40].hex() != plan["plan_sha256"]
        or clock != 80_000_000 or delta & raw
        or (delta | raw).bit_count() != plan["target_epoch"]
        or data[56] != command or data[57:] != bytes(7)
        or any(value in (0, 0xFFFFFFFF) for value in sequences)
        or any((value - 1) % 2 != slot for slot, value in enumerate(sequences))
        or data[6] != int(sequences[1] > sequences[0])
    ):
        raise MaintenanceError("inconsistent maintenance response")
    return {
        "running_slot": data[6], "valid_metadata_sequences": sequences,
        "before_raw": raw, "delta_raw": delta,
        "target_epoch": data[5], "apb_hz": clock,
        "plan_sha256": data[8:40].hex(),
    }


def call(device, payload: bytes) -> bytes:
    cancel = threading.Event()
    timer = threading.Timer(45, cancel.set)
    timer.start()
    try:
        return device.call(0x51, payload, event=cancel)
    finally:
        timer.cancel()


def approval_matches(approval: dict, binding: dict, now: datetime) -> bool:
    try:
        approved_at = datetime.fromisoformat(approval["approved_at"])
        age = (now - approved_at).total_seconds()
        return (
            approval["approved"] is True
            and approval["operation"] == "counter-only-programming"
            and 0 <= age <= 300
            and all(approval.get(key) == value for key, value in binding.items())
        )
    except (KeyError, TypeError, ValueError):
        return False


def consume_approval(path: Path, binding: dict) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise MaintenanceError("approval must be an owner-only regular file")
    approval = json.loads(path.read_text())
    if not approval_matches(approval, binding, datetime.now(UTC)):
        raise MaintenanceError("a fresh approval for this exact operation is required")
    # Consume before dispatch. An uncertain result requires investigation and a
    # new owner approval, never an automatic repeat with the same file.
    with path.with_name(path.name + ".used").open("x") as marker:
        json.dump({"used_at": datetime.now(UTC).isoformat(), **binding}, marker)
        marker.flush()
        os.fsync(marker.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=COMMANDS, default="inspect")
    parser.add_argument("--identity-reference", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--expected-slot0", required=True, type=Path)
    parser.add_argument("--expected-slot1", required=True, type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (args.mode == "program") != (args.approval is not None):
        parser.error("only programming requires --approval")
    root = Path(__file__).resolve().parent.parent
    paths = [args.identity_reference, args.plan, args.expected_slot0,
             args.expected_slot1, args.output]
    if args.approval:
        paths.append(args.approval)
    if any(path.resolve().is_relative_to(root) for path in paths):
        parser.error("device scope, images, approval and evidence must remain outside Git")
    os.umask(0o077)
    output = None
    dispatched = False
    try:
        if version("fido2") != "2.2.1":
            raise MaintenanceError("python-fido2 2.2.1 is required")
        plan = decode_plan(args.plan.read_bytes())
        identity_bytes = args.identity_reference.read_bytes()
        identity = salpa_environment(json.loads(identity_bytes))
        images = [args.expected_slot0.read_bytes(), args.expected_slot1.read_bytes()]
        digests = [hashlib.sha256(image[:-4096]).hexdigest() for image in images]
        binding = {
            "plan_sha256": plan["plan_sha256"], "target_epoch": plan["target_epoch"],
            "before_raw": plan["before_raw"], "slot_content_sha256": digests,
            "usb_identity_reference_sha256": hashlib.sha256(identity_bytes).hexdigest(),
        }
        # Reserve evidence before opening the device or consuming an approval.
        output = args.output.open("x")
        from fido2.hid import CtapHidDevice, list_descriptors
        matches = [
            d for d in list_descriptors()
            if d.vid == int(str(identity["SALPA_USB_VID"]), 0)
            and d.pid == int(str(identity["SALPA_USB_PID"]), 0)
            and d.serial_number == identity["SALPA_USB_SERIAL"]
        ]
        if len(matches) != 1:
            raise MaintenanceError("expected exactly one matching device")
        device = CtapHidDevice(matches[0], open_connection(matches[0]))
        try:
            records = PREVIEW.compare_images(device, images)
            inspected = decode_response(call(device, bytes([0x13])), plan, 0x13)
            if any(
                record["running_slot"] != inspected["running_slot"]
                or record["valid_metadata_sequences"] != inspected["valid_metadata_sequences"]
                for record in records
            ):
                raise MaintenanceError("layout changed during preflight")
            if digests[1 - inspected["running_slot"]] != plan["fallback_sha256"]:
                raise MaintenanceError("fallback differs from the fixed qualified image")
            result = inspected
            if args.mode != "inspect":
                if args.mode == "program":
                    consume_approval(args.approval, binding)
                payload = (bytes([COMMANDS[args.mode]])
                           + bytes.fromhex(plan["plan_sha256"])
                           + b"".join(bytes.fromhex(value) for value in digests))
                dispatched = True
                print("Maintenance request starting; fresh five-second hold and release required.", flush=True)
                result = decode_response(call(device, payload), plan, COMMANDS[args.mode])
                if result != inspected:
                    raise MaintenanceError("qualification changed during physical approval")
        finally:
            device.close()
        json.dump({"captured_at": datetime.now(UTC).isoformat(), "mode": args.mode,
                   "passed": True, "binding": binding, "result": result,
                   "efuse_programming_requested": args.mode == "program",
                   "independent_post_program_readback_required": args.mode == "program"},
                  output, indent=2)
        output.write("\n")
        print("PASS: fixed counter plan " + args.mode)
        return 0
    except Exception as error:
        if output:
            failure = {"passed": False, "mode": args.mode,
                       "request_dispatched": dispatched,
                       "programming_outcome_requires_investigation": dispatched and args.mode == "program",
                       "automatic_retry_allowed": False,
                       "error_type": type(error).__name__}
            if isinstance(error, DeviceMaintenanceError):
                failure["device_status"] = error.status
                if error.transaction_status is not None:
                    failure["transaction_status"] = error.transaction_status
            json.dump(failure, output, indent=2)
        print("Maintenance did not complete; inspect private evidence before any retry.", file=sys.stderr)
        return 1
    finally:
        if output:
            output.close()


if __name__ == "__main__":
    raise SystemExit(main())
