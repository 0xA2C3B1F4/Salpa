from __future__ import annotations

import hashlib
import importlib.util
import io
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "rissokey_usb_ota", ROOT / "tools" / "rissokey-usb-ota.py"
)
assert SPEC is not None and SPEC.loader is not None
OTA = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OTA
SPEC.loader.exec_module(OTA)


def image_bytes(*, chip_id: int = 2, secure_version: int = 3) -> bytes:
    image = bytearray([0xFF] * 8192)
    image[0] = 0xE9
    image[1] = 1
    struct.pack_into("<H", image, 12, chip_id)
    struct.pack_into("<I", image, 32, 0xABCD5432)
    struct.pack_into("<I", image, 36, secure_version)
    image[48:54] = b"2.4.0\0"
    return bytes(image)


def reply(
    *,
    phase: int,
    session: int = 0,
    completed: int = 0,
    total: int = 0,
    status: int = 0,
    slot: int = 0xFF,
) -> bytes:
    current_version = b"2.3.0"
    return (
        bytes([status, 1, phase, slot])
        + struct.pack("<III", session, completed, total)
        + struct.pack("<I", 2)
        + bytes([len(current_version)])
        + current_version
    )


class FakeDevice:
    def __init__(self, image_size: int) -> None:
        self.image_size = image_size
        self.requests: list[bytes] = []
        self.received = 0
        self.erased = False

    def call(self, command: int, request: bytes, on_keepalive=None) -> bytes:
        if command != 0x51:
            raise AssertionError(f"unexpected command {command:#x}")
        self.requests.append(request)
        operation = request[0]
        if operation == OTA.OP_INFO:
            return reply(phase=0)
        if operation == OTA.OP_BEGIN:
            if on_keepalive is not None:
                on_keepalive(object())
            return reply(phase=1, session=7, total=self.image_size, slot=1)
        if operation == OTA.OP_ADVANCE and not self.erased:
            self.erased = True
            return reply(phase=2, session=7, total=self.image_size, slot=1)
        if operation == OTA.OP_WRITE:
            offset = struct.unpack_from("<I", request, 5)[0]
            if offset != self.received:
                raise AssertionError("non-contiguous host write")
            self.received += len(request) - 9
            return reply(
                phase=2,
                session=7,
                completed=self.received,
                total=self.image_size,
                slot=1,
            )
        if operation == OTA.OP_ADVANCE:
            return reply(
                phase=4,
                session=7,
                completed=self.image_size,
                total=self.image_size,
                slot=1,
            )
        raise AssertionError(f"unexpected operation {operation}")


class UsbOtaCliTests(unittest.TestCase):
    def test_load_image_extracts_hash_and_versions(self) -> None:
        image = image_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "signed.bin"
            path.write_bytes(image)
            loaded, metadata = OTA.load_image(path)
        self.assertEqual(loaded, image)
        self.assertEqual(metadata.sha256, hashlib.sha256(image).digest())
        self.assertEqual(metadata.secure_version, 3)
        self.assertEqual(metadata.version, "2.4.0")

    def test_load_image_rejects_another_chip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-chip.bin"
            path.write_bytes(image_bytes(chip_id=9))
            with self.assertRaisesRegex(OTA.UpdateError, "not for ESP32-S2"):
                OTA.load_image(path)

    def test_status_response_is_strictly_decoded(self) -> None:
        status = OTA.decode_status(
            reply(phase=3, session=19, completed=4096, total=8192, slot=1)
        )
        self.assertEqual(status.session_id, 19)
        self.assertEqual(status.current_version, "2.3.0")
        with self.assertRaisesRegex(OTA.UpdateError, "truncated"):
            OTA.decode_status(b"short")

    def test_install_uses_vendor_command_contiguous_chunks_and_activation_last(self) -> None:
        image = image_bytes()
        metadata = OTA.ImageMetadata(
            size=len(image),
            sha256=hashlib.sha256(image).digest(),
            secure_version=3,
            version="2.4.0",
        )
        device = FakeDevice(len(image))
        with redirect_stdout(io.StringIO()):
            OTA.install(device, image, metadata)
        self.assertEqual(device.received, len(image))
        self.assertEqual(device.requests[0], bytes([OTA.OP_INFO]))
        self.assertEqual(device.requests[1][0], OTA.OP_BEGIN)
        self.assertEqual(device.requests[2][0], OTA.OP_ADVANCE)
        self.assertTrue(all(request[0] == OTA.OP_WRITE for request in device.requests[3:-1]))
        self.assertEqual(device.requests[-1][0], OTA.OP_ADVANCE)

    def test_host_rejects_secure_version_rollback_before_begin(self) -> None:
        image = image_bytes(secure_version=1)
        metadata = OTA.ImageMetadata(
            size=len(image),
            sha256=hashlib.sha256(image).digest(),
            secure_version=1,
            version="2.4.0",
        )

        class RollbackDevice(FakeDevice):
            def call(self, command: int, request: bytes, on_keepalive=None) -> bytes:
                if request[0] == OTA.OP_INFO:
                    self.requests.append(request)
                    response = bytearray(reply(phase=0))
                    struct.pack_into("<I", response, 16, 2)
                    return bytes(response)
                return super().call(command, request, on_keepalive)

        device = RollbackDevice(len(image))
        with redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(OTA.UpdateError, "rollback"):
                OTA.install(device, image, metadata)
        self.assertEqual(device.requests, [bytes([OTA.OP_INFO])])


if __name__ == "__main__":
    unittest.main()
