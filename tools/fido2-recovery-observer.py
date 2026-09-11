#!/usr/bin/env python3
"""Record one protected S2 USB recovery attempt without resetting the device."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import importlib.util
from importlib.metadata import version
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import salpa_environment


class Reporter:
    def __init__(self, stream, clock=time.monotonic):
        self.stream = stream
        self.clock = clock
        self.started = clock()
        self.stage = "startup"

    def emit(self, event, **fields):
        record = {"event": event, "stage": self.stage,
                  "utc": datetime.now(UTC).isoformat(),
                  "monotonic_seconds": round(self.clock(), 6),
                  "elapsed_seconds": round(self.clock() - self.started, 6), **fields}
        self.stream.write(json.dumps(record) + "\n")
        self.stream.flush()

    def enter(self, stage):
        self.stage = stage
        self.emit("started")

    def failure(self, error):
        # Native exception messages and reprs can contain serials or HID paths.
        category = ("timeout" if isinstance(error, TimeoutError) else
                    "os_error" if isinstance(error, OSError) else "check_failed")
        fields = {"error_category": category}
        known = {
            "HID receive timed out": "receive_timeout",
            "HID receive loop failed to start": "receive_start_failed",
            "HID receive loop is unavailable": "receive_unavailable",
            "HID receive loop did not stop": "receive_stop_failed",
        }
        if isinstance(error, OSError):
            if str(error) in known:
                fields["transport_error"] = known[str(error)]
            if isinstance(error.errno, int):
                fields["os_errno"] = error.errno
        self.emit("failed", **fields)


def select_descriptors(identity):
    from fido2.hid import list_descriptors
    return [d for d in list_descriptors()
            if d.vid == int(str(identity["SALPA_USB_VID"]), 0)
            and d.pid == int(str(identity["SALPA_USB_PID"]), 0)
            and d.serial_number == identity["SALPA_USB_SERIAL"]]


def wait_for_device(select, report, *, disconnect, timeout, settle,
                    clock=time.monotonic, sleep=time.sleep):
    """Require observed disappearance for a cycle, then stable sampled presence."""
    report.enter("wait_disconnect" if disconnect else "enumeration")
    deadline = clock() + timeout
    previous = None
    stable_since = None
    first = True
    while clock() < deadline:
        matches = select()
        count = len(matches)
        if count != previous:
            report.emit("enumeration_changed", matching_devices=count)
            previous = count
        if count > 1 or (first and disconnect and count != 1):
            raise ValueError("cycle requires exactly one initial device")
        first = False
        if disconnect:
            if count == 0:
                disconnect = False
                report.emit("disconnect_observed")
                report.enter("enumeration")
        elif count == 1:
            if stable_since is None:
                stable_since = clock()
            if clock() - stable_since >= settle:
                report.emit("enumeration_stable", stable_seconds=settle)
                return matches[0]
        else:
            stable_since = None
        sleep(0.2)
    raise TimeoutError("enumeration deadline")


def load_tool(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def probe(descriptor, report, args):
    from fido2.ctap2 import Ctap2
    from fido2.hid import CtapHidDevice
    from fido2_transport import open_connection
    from memory_protection import decode_status as decode_pms
    security = load_tool("recovery_security", "fido2-security-status.py")
    updater = load_tool("recovery_updater", "salpa-usb-ota.py")

    report.enter("hid_open")
    connection = open_connection(descriptor)
    try:
        report.enter("ctaphid_init")
        device = CtapHidDevice(descriptor, connection)
        report.enter("ping")
        payload = bytes(range(80))
        if device.ping(payload) != payload:
            raise ValueError("PING mismatch")
        report.enter("security_status")
        policy = security.read_status(device)
        required = ("secure_boot_enabled", "flash_encryption_enabled",
                    "hardware_jtag_disabled", "rom_download_disabled")
        if (not all(policy[field] for field in required)
                or policy["usb_peripheral_disabled"]
                or policy["hardware_secure_version"] != args.security_version
                or policy["application_secure_version"] != args.security_version):
            raise ValueError("protected policy mismatch")
        report.emit("checked", protected_policy_matches=True)
        report.enter("update_status")
        status = updater.decode_status(device.call(0x51, b"\x00"))
        if (status.status != 0 or status.phase != 0
                or status.current_version != args.firmware_version
                or status.current_secure_version != args.security_version):
            raise ValueError("normal idle image mismatch")
        report.emit("checked", normal_idle_image_matches=True)
        report.enter("pms_status")
        decode_pms(device.call(0x51, b"\x14"), iram_end=args.iram_end,
                   data_start=args.data_start)
        report.emit("checked", pms_matches=True)
        report.enter("get_info")
        info = Ctap2(device).get_info()
        if (set(info.versions) != {"FIDO_2_0", "FIDO_2_1", "FIDO_2_3"}
                or info.options.get("clientPin") is not True):
            raise ValueError("normal GetInfo mismatch")
        report.emit("checked", get_info_matches=True, pin_configured=True)
    finally:
        # Preserve the original failure stage if cleanup also fails.
        failing = sys.exc_info()[0] is not None
        if not failing:
            report.enter("hid_close")
        try:
            connection.close()
        except Exception:
            report.emit("cleanup_failed")
            if not failing:
                raise


def attempt(select, run_probe, report, args, *, clock=time.monotonic, sleep=time.sleep):
    try:
        descriptor = wait_for_device(
            select, report, disconnect=args.wait_for_disconnect,
            timeout=args.wait_seconds, settle=args.settle_seconds, clock=clock, sleep=sleep)
        run_probe(descriptor, report, args)
    except Exception as error:
        report.failure(error)
        # Observe enumeration after failure without retrying HID or CTAP.
        report.enter("after_failure_enumeration")
        for _ in range(6):
            try:
                report.emit("sample", matching_devices=len(select()))
            except Exception as observation_error:
                report.failure(observation_error)
                break
            sleep(1)
        report.emit("result", passed=False, credential_tested=False)
        return 1
    report.emit("result", passed=True, credential_tested=False)
    return 0


def positive_seconds(value):
    parsed = float(value)
    if not math.isfinite(parsed) or not 0 < parsed <= 600:
        raise argparse.ArgumentTypeError("duration must be between 0 and 600 seconds")
    return parsed


def supervise(command, output, timeout):
    """Bound native calls even if a HID backend never returns to Python."""
    report = Reporter(output)
    report.emit("capture_started", schema=1, firmware_write_requested=False,
                reset_requested=False, credential_tested=False)
    try:
        result = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        report.emit("worker_deadline", passed=False)
        return 1
    except Exception:
        report.emit("worker_start_failed", passed=False)
        return 1
    report.emit("capture_finished", passed=result.returncode == 0)
    return 0 if result.returncode == 0 else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new private JSONL file")
    parser.add_argument("--firmware-version", required=True)
    parser.add_argument("--security-version", type=int, required=True)
    parser.add_argument("--iram-end", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--data-start", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--wait-for-disconnect", action="store_true")
    parser.add_argument("--wait-seconds", type=positive_seconds, default=120)
    parser.add_argument("--settle-seconds", type=positive_seconds, default=2)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    if any(path.resolve().is_relative_to(root)
           for path in (args.identity_reference, args.output)):
        parser.error("private references and evidence must stay outside the source tree")
    if args.settle_seconds >= args.wait_seconds or not 0 <= args.security_version <= 16:
        parser.error("invalid settle interval or security version")
    os.umask(0o077)
    if args.worker:
        report = Reporter(sys.stdout)
        try:
            if version("fido2") != "2.2.1":
                raise ValueError("python-fido2 2.2.1 required")
            identity = salpa_environment(json.loads(args.identity_reference.read_text()))
            return attempt(lambda: select_descriptors(identity), probe, report, args)
        except Exception as error:
            report.failure(error)
            return 1
    try:
        with args.output.open("x") as output:
            print("Recording one attempt. Physical actions remain manual.", flush=True)
            command = [sys.executable, "-B", str(Path(__file__).resolve()),
                       *(sys.argv[1:] if argv is None else argv), "--worker"]
            code = supervise(command, output, args.wait_seconds + 60)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        print("Cannot create recovery evidence; no native error details logged.", file=sys.stderr)
        return 1
    print("PASS: transport and status checks" if code == 0 else
          "STOP: attempt failed; inspect recorded stages")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
