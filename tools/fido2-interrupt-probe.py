#!/usr/bin/env python3
"""Test CTAPHID cancellation and same-channel resynchronization on RissoKey."""

from __future__ import annotations

import argparse
import os
import signal
import struct
from contextlib import contextmanager
from importlib.metadata import version
from threading import Event
from typing import Iterator

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import (
    CTAPHID,
    STATUS,
    TYPE_INIT,
    CtapHidDevice,
    list_descriptors,
    open_connection,
)

FIDO2_VERSION = "2.2.1"
OPERATION_TIMEOUT_SECONDS = 5


def usb_id(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("USB ID must fit in 16 bits")
    return parsed


@contextmanager
def operation_timeout() -> Iterator[None]:
    def timeout_handler(_signum: int, _frame: object) -> None:
        raise TimeoutError("device did not complete the interrupt handshake")

    previous = signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, OPERATION_TIMEOUT_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def open_device(vid: int, pid: int) -> CtapHidDevice:
    matches = [
        descriptor
        for descriptor in list_descriptors()
        if descriptor.vid == vid and descriptor.pid == pid
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one matching FIDO HID device, found {len(matches)}")
    return CtapHidDevice(matches[0], open_connection(matches[0]))


def test_cancel(vid: int, pid: int) -> None:
    device = open_device(vid, pid)
    cancel = Event()
    saw_up_needed = False

    def on_keepalive(status: STATUS) -> None:
        nonlocal saw_up_needed
        if status == STATUS.UPNEEDED:
            saw_up_needed = True
            cancel.set()

    try:
        with operation_timeout():
            try:
                Ctap2(device).selection(event=cancel, on_keepalive=on_keepalive)
            except CtapError as error:
                if error.code != CtapError.ERR.KEEPALIVE_CANCEL:
                    raise SystemExit(f"CANCEL returned {error.code.name}") from error
            else:
                raise SystemExit("Selection unexpectedly succeeded after CANCEL")
        if not saw_up_needed:
            raise SystemExit("CANCEL test did not observe UP_NEEDED")
        Ctap2(device).get_info()
    finally:
        device.close()


def send_initial_packet(device: CtapHidDevice, command: CTAPHID, payload: bytes) -> None:
    packet = struct.pack(
        ">IBH", device._channel_id, TYPE_INIT | command, len(payload)
    ) + payload
    device._connection.write_packet(packet.ljust(device._packet_size, b"\0"))


def test_resynchronization(vid: int, pid: int) -> None:
    device = open_device(vid, pid)
    nonce = os.urandom(8)
    try:
        with operation_timeout():
            send_initial_packet(device, CTAPHID.CBOR, bytes([Ctap2.CMD.SELECTION]))
            keepalive = device._connection.read_packet()
            channel, command, length, status = struct.unpack_from(">IBHB", keepalive)
            if (
                channel != device._channel_id
                or command != TYPE_INIT | CTAPHID.KEEPALIVE
                or length != 1
                or status != STATUS.UPNEEDED
            ):
                raise SystemExit("resynchronization test did not receive UP_NEEDED")

            send_initial_packet(device, CTAPHID.INIT, nonce)
            response = device._connection.read_packet()
            channel, command, length = struct.unpack_from(">IBH", response)
            if channel != device._channel_id or command != TYPE_INIT | CTAPHID.INIT:
                raise SystemExit("resynchronization did not return CTAPHID_INIT")
            if length < 17 or response[7:15] != nonce:
                raise SystemExit("resynchronization returned an invalid INIT payload")
            if struct.unpack_from(">I", response, 15)[0] != device._channel_id:
                raise SystemExit("resynchronization changed the allocated channel")
        Ctap2(device).get_info()
    finally:
        device.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vid", type=usb_id)
    parser.add_argument("pid", type=usb_id)
    args = parser.parse_args()

    installed_version = version("fido2")
    if installed_version != FIDO2_VERSION:
        raise SystemExit(
            f"this probe requires python-fido2 {FIDO2_VERSION}, found {installed_version}"
        )

    try:
        test_cancel(args.vid, args.pid)
        print("passed: CANCEL returned KEEPALIVE_CANCEL and the channel recovered")
        test_resynchronization(args.vid, args.pid)
        print("passed: same-channel INIT aborted Selection and preserved the channel")
    except (OSError, TimeoutError) as error:
        raise SystemExit(
            "device did not complete the CTAPHID interrupt handshake"
        ) from error


if __name__ == "__main__":
    main()
