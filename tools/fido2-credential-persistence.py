#!/usr/bin/env python3
"""Create or assert a protected ES256 credential for persistence tests."""

from __future__ import annotations

import argparse
import os
import stat
from importlib.metadata import version
from pathlib import Path
from typing import Any, Mapping

from fido2 import cbor
from fido2.attestation import PackedAttestation
from fido2.cose import CoseKey
from fido2.ctap2 import Ctap2
from fido2.hid import STATUS, CtapHidDevice, list_descriptors, open_connection

FIDO2_VERSION = "2.2.1"
RP_ID = "persistence.rissokey.invalid"
STATE_VERSION = 1


def usb_id(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("USB ID must fit in 16 bits")
    return parsed


def open_device(vid: int, pid: int) -> CtapHidDevice:
    matches = [
        descriptor
        for descriptor in list_descriptors()
        if descriptor.vid == vid and descriptor.pid == pid
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one matching FIDO HID device, found {len(matches)}")
    return CtapHidDevice(matches[0], open_connection(matches[0]))


def user_presence_notice():
    announced = False

    def notice(status: STATUS) -> None:
        nonlocal announced
        if status == STATUS.UPNEEDED and not announced:
            print("waiting: press and release the authenticator user-presence button", flush=True)
            announced = True

    return notice


def write_state(path: Path, state: Mapping[int, Any]) -> None:
    encoded = cbor.encode(state)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def read_state(path: Path) -> Mapping[int, Any]:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise SystemExit(f"state file mode must be 0600, found {mode:04o}")
    state = cbor.decode(path.read_bytes())
    if not isinstance(state, dict) or state.get(1) != STATE_VERSION:
        raise SystemExit("unsupported or malformed persistence state")
    if state.get(2) != RP_ID or not isinstance(state.get(3), bytes):
        raise SystemExit("persistence state has invalid credential metadata")
    if not isinstance(state.get(4), dict):
        raise SystemExit("persistence state has no credential public key")
    return state


def create_credential(vid: int, pid: int, state_path: Path, attestation_certificate: Path | None = None) -> None:
    if state_path.exists():
        raise SystemExit("refusing to overwrite an existing persistence state file")
    expected_certificate = attestation_certificate.read_bytes() if attestation_certificate is not None else None

    device = open_device(vid, pid)
    try:
        client_data_hash = os.urandom(32)
        response = Ctap2(device).make_credential(
            client_data_hash,
            {"id": RP_ID, "name": "RissoKey persistence probe"},
            {
                "id": os.urandom(32),
                "name": "persistence-probe",
                "displayName": "RissoKey persistence probe",
            },
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
            on_keepalive=user_presence_notice(),
        )
        credential = response.auth_data.credential_data
        if credential is None or credential.public_key.get(3) != -7:
            raise SystemExit("authenticator did not return an ES256 credential")
        if expected_certificate is not None:
            if response.fmt != "packed" or response.att_stmt.get("x5c") != [expected_certificate]:
                raise SystemExit("attestation certificate differs from the independently expected identity")
            PackedAttestation().verify(response.att_stmt, response.auth_data, client_data_hash)
            print("verified: packed attestation signature and independently expected certificate")
        write_state(
            state_path,
            {
                1: STATE_VERSION,
                2: RP_ID,
                3: credential.credential_id,
                4: dict(credential.public_key),
            },
        )
    finally:
        device.close()
    print("created: ES256 test credential; protected state saved with mode 0600")


def assert_credential(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    credential_id = state[3]
    public_key = CoseKey.parse(state[4])
    client_data_hash = os.urandom(32)

    device = open_device(vid, pid)
    try:
        assertion = Ctap2(device).get_assertion(
            RP_ID,
            client_data_hash,
            allow_list=[{"type": "public-key", "id": credential_id}],
            on_keepalive=user_presence_notice(),
        )
        if assertion.credential.get("id") != credential_id:
            raise SystemExit("authenticator returned a different credential")
        assertion.verify(client_data_hash, public_key)
    finally:
        device.close()
    print("passed: assertion signature verified with the saved credential public key")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "assert"))
    parser.add_argument("vid", type=usb_id)
    parser.add_argument("pid", type=usb_id)
    parser.add_argument("state", type=Path)
    parser.add_argument("--attestation-certificate", type=Path,
                        help="expected DER certificate; verify packed attestation during creation")
    args = parser.parse_args()

    installed_version = version("fido2")
    if installed_version != FIDO2_VERSION:
        raise SystemExit(
            f"this probe requires python-fido2 {FIDO2_VERSION}, found {installed_version}"
        )

    if args.mode == "create":
        create_credential(args.vid, args.pid, args.state, args.attestation_certificate)
    else:
        assert_credential(args.vid, args.pid, args.state)


if __name__ == "__main__":
    main()
