"""Recovery evidence must retain transient failures without exposing identity."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "recovery_observer", Path(__file__).resolve().parents[1] / "tools/fido2-recovery-observer.py")
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.output = io.StringIO()
        self.report = OBSERVER.Reporter(self.output, self.clock)
        self.args = SimpleNamespace(wait_for_disconnect=False, wait_seconds=3,
                                    settle_seconds=0.4)

    def events(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def run_attempt(self, select, probe):
        return OBSERVER.attempt(select, probe, self.report, self.args,
                                clock=self.clock, sleep=self.clock.sleep)

    def test_cycle_needs_observed_disappearance(self):
        self.args.wait_for_disconnect = True
        probes = []
        self.assertEqual(self.run_attempt(lambda: [object()], lambda *a: probes.append(a)), 1)
        self.assertFalse(probes)
        failure = next(e for e in self.events() if e["event"] == "failed")
        self.assertEqual(failure["stage"], "wait_disconnect")
        self.assertEqual(failure["error_category"], "timeout")

    def test_cycle_rejects_initially_absent_device(self):
        self.args.wait_for_disconnect = True
        self.assertEqual(self.run_attempt(lambda: [], lambda *a: self.fail("probe")), 1)
        self.assertNotIn("disconnect_observed", [e["event"] for e in self.events()])

    def test_transient_reappearance_restarts_settle_interval(self):
        self.args.wait_for_disconnect = True
        descriptor = object()
        counts = iter([1, 0, 1, 0, 1, 1, 1, 1])
        probe_times = []
        def select():
            return [descriptor] * next(counts, 1)
        self.assertEqual(self.run_attempt(select, lambda *a: probe_times.append(self.clock())), 0)
        self.assertEqual(len(probe_times), 1)
        self.assertGreaterEqual(probe_times[0], 1.2)
        self.assertEqual([e["matching_devices"] for e in self.events()
                          if e["event"] == "enumeration_changed"], [1, 0, 1, 0, 1])

    def test_duplicate_identity_never_opens_either_device(self):
        self.assertEqual(self.run_attempt(lambda: [object(), object()],
                                         lambda *a: self.fail("probe")), 1)

    def test_hid_failure_retains_stage_without_retry_or_private_text(self):
        probes = []
        def probe(descriptor, report, args):
            probes.append(descriptor)
            report.enter("ctaphid_init")
            raise OSError("private serial and native path")
        self.assertEqual(self.run_attempt(lambda: [object()], probe), 1)
        self.assertEqual(len(probes), 1)
        failure = next(e for e in self.events() if e["event"] == "failed")
        self.assertEqual(failure["stage"], "ctaphid_init")
        self.assertEqual(failure["error_category"], "os_error")
        self.assertNotIn("private serial", self.output.getvalue())
        self.assertEqual(sum(e["event"] == "sample" for e in self.events()), 6)
        self.assertFalse(self.events()[-1]["passed"])

    def test_baseline_does_not_claim_reset_or_credential_acceptance(self):
        self.assertEqual(self.run_attempt(lambda: [object()], lambda *a: None), 0)
        self.assertFalse(self.events()[-1]["credential_tested"])
        self.assertNotIn("disconnect_observed", [e["event"] for e in self.events()])

    def test_known_transport_error_and_errno_are_retained_without_native_text(self):
        self.report.failure(OSError("HID receive timed out"))
        self.report.failure(OSError(5, "private native path"))
        self.assertEqual(self.events()[0]["transport_error"], "receive_timeout")
        self.assertEqual(self.events()[1]["os_errno"], 5)
        self.assertNotIn("private native path", self.output.getvalue())

    def test_native_hang_is_bounded_by_parent_and_marked_failed(self):
        with patch.object(OBSERVER.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("worker", 2)) as run:
            self.assertEqual(OBSERVER.supervise(["worker"], self.output, 2), 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 2)
        self.assertEqual(self.events()[-1]["event"], "worker_deadline")
        self.assertFalse(self.events()[-1]["passed"])

    def test_worker_crash_never_becomes_success(self):
        with patch.object(OBSERVER.subprocess, "run", return_value=SimpleNamespace(returncode=-9)):
            self.assertEqual(OBSERVER.supervise(["worker"], self.output, 2), 1)
        self.assertFalse(self.events()[-1]["passed"])

    def test_real_blocked_worker_is_terminated_with_partial_evidence_intact(self):
        with tempfile.TemporaryFile(mode="w+") as output:
            command = [OBSERVER.sys.executable, "-u", "-c",
                       "import time; print('{\"stage\":\"hid_open\"}', flush=True); time.sleep(10)"]
            self.assertEqual(OBSERVER.supervise(command, output, 0.5), 1)
            output.seek(0)
            events = [json.loads(line) for line in output]
        self.assertEqual(events[-2]["stage"], "hid_open")
        self.assertEqual(events[-1]["event"], "worker_deadline")

    def test_durations_reject_nan_infinity_and_unbounded_waits(self):
        for value in ("nan", "inf", "0", "-1", "601"):
            with self.subTest(value=value), self.assertRaises(OBSERVER.argparse.ArgumentTypeError):
                OBSERVER.positive_seconds(value)

    def test_probe_only_reads_status_and_always_closes_on_mismatch(self):
        requests = []
        connection = SimpleNamespace(close=lambda: requests.append("close"))
        device = SimpleNamespace(
            ping=lambda payload: payload,
            call=lambda command, payload: requests.append((command, payload)))
        policy = {name: True for name in (
            "secure_boot_enabled", "flash_encryption_enabled",
            "hardware_jtag_disabled", "rom_download_disabled")}
        policy.update(usb_peripheral_disabled=False, hardware_secure_version=5,
                      application_secure_version=5)
        security = SimpleNamespace(read_status=lambda dev: policy)
        status = SimpleNamespace(status=0, phase=0, current_version="0.1.0",
                                 current_secure_version=5)
        updater = SimpleNamespace(decode_status=lambda data: status)
        info = SimpleNamespace(versions=["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"],
                               options={"clientPin": True})
        modules = {
            "fido2.ctap2": SimpleNamespace(Ctap2=lambda dev: SimpleNamespace(get_info=lambda: info)),
            "fido2.hid": SimpleNamespace(CtapHidDevice=lambda *a: device),
            "fido2_transport": SimpleNamespace(open_connection=lambda d: connection),
            "memory_protection": SimpleNamespace(decode_status=lambda *a, **kw: None),
        }
        args = SimpleNamespace(security_version=5, firmware_version="0.1.0",
                               iram_end=0x40028000, data_start=0x3ffb8000)
        with patch.dict(OBSERVER.sys.modules, modules), patch.object(
                OBSERVER, "load_tool", side_effect=lambda name, file:
                security if name == "recovery_security" else updater):
            OBSERVER.probe(object(), self.report, args)
            self.assertEqual(requests, [(0x51, b"\x00"), (0x51, b"\x14"), "close"])
            requests.clear()
            policy["secure_boot_enabled"] = False
            with self.assertRaises(ValueError):
                OBSERVER.probe(object(), self.report, args)
            self.assertEqual(requests, ["close"])
            self.assertEqual(self.report.stage, "security_status")


if __name__ == "__main__":
    unittest.main()
