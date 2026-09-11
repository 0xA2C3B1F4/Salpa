"""Exercise receiver lifetime, ordering and failure without a USB device."""

import ast
import importlib.util
from pathlib import Path
from queue import Queue
import threading
import time
from types import SimpleNamespace
from typing import Any
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "fido2_transport", Path(__file__).resolve().parents[1] / "tools/fido2_transport.py"
)
TRANSPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSPORT)


class NativeFixture:
    def __init__(self, fail_start=False):
        self.events = []
        self.scheduled = threading.Event()
        self.delivery = Queue()
        self.fail_start = fail_start
        fixture = self

        class Connection:
            def __init__(self, descriptor):
                self.handle = descriptor
                self.read_queue = Queue()
                fixture.connection = self

            def write_packet(self, packet):
                fixture.events.append(("write", packet))

            def close(self):
                fixture.events.append("close callback")

        self.native = SimpleNamespace(
            MacCtapHidConnection=Connection,
            K_CF_RUNLOOP_DEFAULT_MODE=object(),
            cf=SimpleNamespace(
                CFRunLoopGetCurrent=lambda: threading.get_ident(),
                CFRunLoopRunInMode=self.run,
            ),
            iokit=SimpleNamespace(
                IOHIDDeviceScheduleWithRunLoop=self.schedule,
                IOHIDDeviceUnscheduleFromRunLoop=self.unschedule,
            ),
        )

    def schedule(self, *args):
        if self.fail_start:
            raise RuntimeError("private native failure")
        self.events.append("schedule")
        self.scheduled.set()

    def unschedule(self, *args):
        self.events.append("unschedule")
        self.scheduled.clear()

    def run(self, mode, duration, return_after_source):
        self.assert_continuous = not return_after_source
        if not self.delivery.empty():
            self.connection.read_queue.put(self.delivery.get_nowait())
        time.sleep(0.001)


class ReceiverTests(unittest.TestCase):
    def connection(self):
        fixture = NativeFixture()
        connection = TRANSPORT._connection_class(fixture.native)("test descriptor")
        self.addCleanup(connection.close)
        return fixture, connection

    def test_reception_stays_scheduled_between_application_reads(self):
        fixture, connection = self.connection()
        fixture.delivery.put(b"keepalive")
        self.assertEqual(connection.read_packet(), b"keepalive")
        # The host is busy between reads. Both the initial reply and its next
        # packet must still reach the queue, without another schedule call.
        fixture.delivery.put(b"initial reply")
        fixture.delivery.put(b"continuation zero")
        self.assertEqual(connection.read_packet(), b"initial reply")
        self.assertEqual(connection.read_packet(), b"continuation zero")
        self.assertEqual(fixture.events, ["schedule"])
        self.assertTrue(fixture.scheduled.is_set())
        self.assertTrue(fixture.assert_continuous)

    def test_burst_order_and_packet_contents_are_preserved(self):
        fixture, connection = self.connection()
        packets = [bytes([number]) * 64 for number in range(32)]
        for packet in packets:
            fixture.delivery.put(packet)
        self.assertEqual([connection.read_packet() for _ in packets], packets)
        connection.write_packet(b"outgoing packet")
        self.assertIn(("write", b"outgoing packet"), fixture.events)

    def test_idle_read_has_a_deadline(self):
        _, connection = self.connection()
        connection.READ_TIMEOUT = 0.01
        with self.assertRaisesRegex(OSError, "timed out"):
            connection.read_packet()

    def test_close_stops_reader_before_removing_callback_and_is_idempotent(self):
        fixture, connection = self.connection()
        connection.close()
        connection.close()
        self.assertEqual(fixture.events, ["schedule", "unschedule", "close callback"])
        self.assertFalse(connection._reader.is_alive())
        with self.assertRaisesRegex(OSError, "unavailable"):
            connection.read_packet()

    def test_start_failure_is_sanitized_and_closes_callback(self):
        fixture = NativeFixture(fail_start=True)
        with self.assertRaisesRegex(OSError, "HID receive loop failed to start"):
            TRANSPORT._connection_class(fixture.native)("test descriptor")
        self.assertEqual(fixture.events, ["close callback"])

    def test_reader_failure_rejects_further_reads(self):
        fixture, connection = self.connection()

        def fail(*args):
            raise RuntimeError("private native failure")

        fixture.native.cf.CFRunLoopRunInMode = fail
        connection._reader.join(1)
        self.assertFalse(connection._reader.is_alive())
        with self.assertRaisesRegex(OSError, "unavailable"):
            connection.read_packet()

    def test_unreviewed_macos_library_version_is_rejected_before_open(self):
        with patch.object(TRANSPORT.sys, "platform", "darwin"), \
                patch.object(TRANSPORT, "version", return_value="9.0.0"):
            with self.assertRaisesRegex(RuntimeError, "requires python-fido2 2.2.1"):
                TRANSPORT.open_connection("test descriptor")


class ToolConnectionTests(unittest.TestCase):
    def opener(self, filename, descriptors):
        path = Path(__file__).resolve().parents[1] / "tools" / filename
        tree = ast.parse(path.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("matching_devices", "open_device")]
        calls = []

        def connect(descriptor):
            calls.append(descriptor)
            return "connection"

        hid = SimpleNamespace(CtapHidDevice=lambda descriptor, connection: (descriptor, connection),
                              list_descriptors=lambda: descriptors)
        namespace = dict(CtapHidDevice=hid.CtapHidDevice,
                         list_descriptors=hid.list_descriptors, open_connection=connect,
                         Any=Any, UpdateError=RuntimeError)
        code = compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec")
        exec(code, namespace)
        return namespace["open_device"], calls, hid

    def test_tools_keep_unique_descriptor_selection_and_pass_connection_to_hid(self):
        files = ("fido2-credential-persistence.py", "fido2-interrupt-probe.py",
                 "fido2-pin-resident-probe.py", "salpa-usb-ota.py")
        target = SimpleNamespace(vid=1, pid=2)
        other = SimpleNamespace(vid=3, pid=4)
        for filename in files:
            with self.subTest(filename=filename):
                opener, calls, hid = self.opener(filename, [other, target])
                with patch.dict("sys.modules", {"fido2.hid": hid}):
                    self.assertEqual(opener(1, 2), (target, "connection"))
                self.assertEqual(calls, [target])

    def test_ambiguous_devices_are_rejected_before_opening(self):
        target = SimpleNamespace(vid=1, pid=2)
        opener, calls, _ = self.opener("fido2-credential-persistence.py", [target, target])
        with self.assertRaises(SystemExit):
            opener(1, 2)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
