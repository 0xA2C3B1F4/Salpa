"""Keep macOS HID reception scheduled for the lifetime of a FIDO connection.

python-fido2 2.2.1 schedules and unschedules its macOS run loop around reads.
Salpa acceptance testing observed missing initial assertion reply packets
with that receiver; continuous scheduling delivered verifiable replies with
the same firmware. CTAP framing, authentication and verification stay upstream.
"""

from __future__ import annotations

from importlib.metadata import version
from queue import Empty
import sys
import threading


def _connection_class(native):
    """Load native bindings lazily so other platforms keep their own backend."""

    class ContinuousConnection(native.MacCtapHidConnection):
        READ_TIMEOUT = 6
        START_TIMEOUT = 5
        CLOSE_TIMEOUT = 2

        def __init__(self, descriptor):
            super().__init__(descriptor)
            self._stop = threading.Event()
            self._ready = threading.Event()
            self._failure = False
            self._closed = False
            self._reader = threading.Thread(target=self._receive_loop, daemon=True)
            self._reader.start()
            if not self._ready.wait(self.START_TIMEOUT) or self._failure:
                self.close()
                raise OSError("HID receive loop failed to start")

        def _receive_loop(self):
            scheduled = False
            try:
                loop = native.cf.CFRunLoopGetCurrent()
                native.iokit.IOHIDDeviceScheduleWithRunLoop(
                    self.handle, loop, native.K_CF_RUNLOOP_DEFAULT_MODE
                )
                scheduled = True
                self._ready.set()
                while not self._stop.is_set():
                    native.cf.CFRunLoopRunInMode(
                        native.K_CF_RUNLOOP_DEFAULT_MODE, 0.1, False
                    )
            except Exception:
                # Native exceptions can contain device identifiers.
                self._failure = True
                self._ready.set()
            finally:
                if scheduled:
                    try:
                        native.iokit.IOHIDDeviceUnscheduleFromRunLoop(
                            self.handle, loop, native.K_CF_RUNLOOP_DEFAULT_MODE
                        )
                    except Exception:
                        self._failure = True

        def read_packet(self):
            if self._closed or self._failure:
                raise OSError("HID receive loop is unavailable")
            try:
                return self.read_queue.get(timeout=self.READ_TIMEOUT)
            except Empty:
                raise OSError("HID receive timed out") from None

        def close(self):
            if self._closed:
                return
            self._stop.set()
            self._reader.join(self.CLOSE_TIMEOUT)
            if self._reader.is_alive():
                # Keep the native callback alive until its reader has stopped.
                raise OSError("HID receive loop did not stop")
            super().close()
            self._closed = True

    return ContinuousConnection


def open_connection(descriptor):
    """Open the already selected descriptor without changing identity policy."""
    if sys.platform != "darwin":
        from fido2.hid import open_connection as upstream_open

        return upstream_open(descriptor)

    if version("fido2") != "2.2.1":
        raise RuntimeError("macOS receiver requires python-fido2 2.2.1")
    from fido2.hid import macos

    return _connection_class(macos)(descriptor)
