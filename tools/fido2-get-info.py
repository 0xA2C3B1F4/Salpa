#!/usr/bin/env python3
"""Validate production RissoKey CTAPHID INIT, fragmented PING, and GetInfo."""

from __future__ import annotations

import argparse

from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice, list_descriptors, open_connection


def usb_id(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("USB ID must fit in 16 bits")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vid", type=usb_id)
    parser.add_argument("pid", type=usb_id)
    args = parser.parse_args()

    matches = [
        descriptor
        for descriptor in list_descriptors()
        if descriptor.vid == args.vid and descriptor.pid == args.pid
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one matching FIDO HID device, found {len(matches)}")

    device = CtapHidDevice(matches[0], open_connection(matches[0]))
    try:
        ping = bytes(range(80))
        if device.ping(ping) != ping:
            raise SystemExit("fragmented CTAPHID PING response did not match")

        info = Ctap2(device).get_info()
        expected_versions = {"U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"}
        if set(info.versions) != expected_versions:
            raise SystemExit(f"unexpected versions: {info.versions!r}")
        expected_extensions = {
            "credProtect",
            "credBlob",
            "hmac-secret",
            "hmac-secret-mc",
            "minPinLength",
            "thirdPartyPayment",
        }
        if set(info.extensions or []) != expected_extensions:
            raise SystemExit(f"unexpected extensions: {info.extensions!r}")
        expected_options = {
            "rk": True,
            "up": True,
            "plat": False,
            "alwaysUv": False,
            "credMgmt": True,
            "authnrCfg": True,
            "largeBlobs": False,
            "pinUvAuthToken": True,
            "setMinPINLength": True,
            "makeCredUvNotRqd": True,
        }
        client_pin = info.options.get("clientPin")
        options_without_client_pin = {
            key: value for key, value in info.options.items() if key != "clientPin"
        }
        if client_pin not in (False, True) or options_without_client_pin != expected_options:
            raise SystemExit(f"unexpected options: {info.options!r}")
        if info.aaguid.hex() != "989e2cc205df4e64806822683886e8b3":
            raise SystemExit(f"unexpected AAGUID: {info.aaguid.hex()}")
        if info.max_msg_size != 1024:
            raise SystemExit(f"unexpected maxMsgSize: {info.max_msg_size!r}")
        if info.transports != ["usb"]:
            raise SystemExit(f"unexpected transports: {info.transports!r}")
        algorithms = {
            (algorithm.get("alg"), algorithm.get("type"))
            for algorithm in info.algorithms or []
        }
        if algorithms != {(-8, "public-key"), (-7, "public-key")}:
            raise SystemExit(f"unexpected algorithms: {info.algorithms!r}")
        if info.pin_uv_protocols != [2, 1]:
            raise SystemExit(f"unexpected PIN/UV protocols: {info.pin_uv_protocols!r}")

        print(
            "passed: CTAPHID INIT, 80-byte PING, and authenticatorGetInfo; "
            f"protocol={device.version}, firmware={device.device_version}, "
            f"capabilities=0x{device.capabilities:02x}, clientPin={client_pin}"
        )
    finally:
        device.close()


if __name__ == "__main__":
    main()
