#!/usr/bin/env python3
"""Exercise ClientPIN, discoverable credentials, and reset without logging secrets."""

from __future__ import annotations

import argparse
import sys
import hashlib
import os
import secrets
import stat
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any, Mapping

from fido2 import cbor
from fido2.attestation import Attestation, AttestationType
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.hid import CtapHidDevice, list_descriptors

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fido2_transport import open_connection

FIDO2_VERSION = "2.2.1"
RP_ID = "resident.rissokey.invalid"
STATE_VERSION = 1

K_VERSION = 1
K_RP_ID = 2
K_PIN = 3
K_USER_ID = 4
K_AAGUID = 5
K_INITIAL_RETRIES = 6
K_BASELINE_CREDENTIALS = 7
K_CREDENTIAL_ID = 8
K_PUBLIC_KEY = 9
K_ATTESTATION_CERT_HASH = 10
K_CREDENTIAL_DELETED = 11
K_RESET_VERIFIED = 12


def usb_id(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("USB ID must fit in 16 bits")
    return parsed


def matching_devices(vid: int, pid: int):
    return [
        descriptor
        for descriptor in list_descriptors()
        if descriptor.vid == vid and descriptor.pid == pid
    ]


def open_device(vid: int, pid: int) -> CtapHidDevice:
    matches = matching_devices(vid, pid)
    if len(matches) != 1:
        raise SystemExit(f"expected one matching FIDO HID device, found {len(matches)}")
    return CtapHidDevice(matches[0], open_connection(matches[0]))


def wait_for_reset_reenumeration(vid: int, pid: int) -> CtapHidDevice:
    if len(matching_devices(vid, pid)) != 1:
        raise SystemExit("authenticator must be present before waiting for RESET")
    print("waiting: press the authenticator RESET button", flush=True)
    deadline = time.monotonic() + 60
    while matching_devices(vid, pid):
        if time.monotonic() >= deadline:
            raise SystemExit("timed out waiting for USB disconnect after RESET")
        time.sleep(0.02)
    while time.monotonic() < deadline:
        matches = matching_devices(vid, pid)
        if len(matches) == 1:
            return CtapHidDevice(matches[0], open_connection(matches[0]))
        if len(matches) > 1:
            raise SystemExit("multiple matching authenticators appeared after RESET")
        time.sleep(0.02)
    raise SystemExit("timed out waiting for USB re-enumeration after RESET")


def require_private_parent(path: Path) -> None:
    mode = stat.S_IMODE(path.parent.stat().st_mode)
    if mode != 0o700:
        raise SystemExit(f"state directory mode must be 0700, found {mode:04o}")


def sync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_state(path: Path, state: Mapping[int, Any]) -> None:
    require_private_parent(path)
    encoded = cbor.encode(state)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    sync_parent(path)


def replace_state(path: Path, state: Mapping[int, Any]) -> None:
    require_private_parent(path)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    try:
        write_new_state(temporary, state)
        os.replace(temporary, path)
        sync_parent(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_state(path: Path) -> dict[int, Any]:
    require_private_parent(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise SystemExit(f"state file mode must be 0600, found {mode:04o}")
    try:
        decoded = cbor.decode(path.read_bytes())
    except Exception as error:
        raise SystemExit("malformed protected state file") from error
    if not isinstance(decoded, dict) or decoded.get(K_VERSION) != STATE_VERSION:
        raise SystemExit("unsupported protected state file")
    if decoded.get(K_RP_ID) != RP_ID:
        raise SystemExit("protected state has an unexpected RP ID")
    if not isinstance(decoded.get(K_PIN), str) or len(decoded[K_PIN]) != 8:
        raise SystemExit("protected state has invalid PIN metadata")
    if not isinstance(decoded.get(K_USER_ID), bytes):
        raise SystemExit("protected state has invalid user metadata")
    if not isinstance(decoded.get(K_AAGUID), bytes):
        raise SystemExit("protected state has invalid authenticator metadata")
    return decoded


def user_presence_notice():
    announced = False

    def notice(_status: int) -> None:
        nonlocal announced
        if not announced:
            print("waiting: press the authenticator BOOT button", flush=True)
            announced = True

    return notice


def pin_client(ctap: Ctap2) -> ClientPin:
    if not ClientPin.is_supported(ctap.info):
        raise SystemExit("authenticator does not advertise ClientPIN")
    return ClientPin(ctap)


def pin_token(
    client_pin: ClientPin,
    pin: str,
    permission: ClientPin.PERMISSION,
    rp_id: str | None = None,
) -> bytes:
    return client_pin.get_pin_token(pin, permission, rp_id)


def verify_basic_attestation(response: Any, client_data_hash: bytes) -> bytes:
    result = Attestation.for_type(response.fmt)().verify(
        response.att_stmt, response.auth_data, client_data_hash
    )
    if result.attestation_type != AttestationType.BASIC or not result.trust_path:
        raise SystemExit("authenticator did not return basic attestation")
    return hashlib.sha256(result.trust_path[0]).digest()


def set_pin(vid: int, pid: int, state_path: Path) -> None:
    if state_path.exists():
        raise SystemExit("refusing to overwrite an existing protected state file")

    device = open_device(vid, pid)
    try:
        ctap = Ctap2(device)
        if ctap.info.options.get("clientPin") is not False:
            raise SystemExit("authenticator PIN is already configured")
        client_pin = pin_client(ctap)
        initial_retries, _ = client_pin.get_pin_retries()
        if initial_retries < 2:
            raise SystemExit("unexpectedly low initial PIN retry count")

        pin = f"{secrets.randbelow(100_000_000):08d}"
        write_new_state(
            state_path,
            {
                K_VERSION: STATE_VERSION,
                K_RP_ID: RP_ID,
                K_PIN: pin,
                K_USER_ID: os.urandom(32),
                K_AAGUID: bytes(ctap.info.aaguid),
                K_INITIAL_RETRIES: initial_retries,
            },
        )
        client_pin.set_pin(pin)
        if ctap.get_info().options.get("clientPin") is not True:
            raise SystemExit("PIN setup returned without enabling ClientPIN")
        retries_after, _ = client_pin.get_pin_retries()
        if retries_after != initial_retries:
            raise SystemExit("PIN setup unexpectedly changed the retry count")
    finally:
        device.close()
    print(f"passed: temporary PIN configured; retry count is {initial_retries}")


def test_retries(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    pin = state[K_PIN]
    initial_retries = state[K_INITIAL_RETRIES]
    wrong_pin = f"{(int(pin) + 1) % 100_000_000:08d}"

    device = open_device(vid, pid)
    try:
        ctap = Ctap2(device)
        client_pin = pin_client(ctap)
        before, _ = client_pin.get_pin_retries()
        if before != initial_retries:
            raise SystemExit("PIN retry count was not at its recorded baseline")
        try:
            pin_token(
                client_pin,
                wrong_pin,
                ClientPin.PERMISSION.MAKE_CREDENTIAL,
                RP_ID,
            )
        except CtapError as error:
            if error.code != CtapError.ERR.PIN_INVALID:
                raise
        else:
            raise SystemExit("authenticator accepted the intentionally wrong PIN")

        after_wrong, _ = client_pin.get_pin_retries()
        if after_wrong != before - 1:
            raise SystemExit("one wrong PIN attempt did not decrement retries by one")

        token = pin_token(client_pin, pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        after_correct, _ = client_pin.get_pin_retries()
        if after_correct != initial_retries:
            raise SystemExit("a correct PIN did not restore the retry baseline")
        metadata = CredentialManagement(ctap, client_pin.protocol, token).get_metadata()
        baseline = metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
        state[K_BASELINE_CREDENTIALS] = baseline
        replace_state(state_path, state)
    finally:
        device.close()
    print(
        "passed: one wrong PIN decremented retries and a correct PIN restored "
        f"the count to {initial_retries}"
    )


def create_resident(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    if K_BASELINE_CREDENTIALS not in state:
        raise SystemExit("retry test must run before resident credential creation")
    if K_CREDENTIAL_ID in state:
        raise SystemExit("protected state already contains a credential")

    device = open_device(vid, pid)
    try:
        ctap = Ctap2(device)
        client_pin = pin_client(ctap)
        pin = state[K_PIN]
        baseline = state[K_BASELINE_CREDENTIALS]

        management_token = pin_token(
            client_pin, pin, ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
        management = CredentialManagement(
            ctap, client_pin.protocol, management_token
        )
        before = management.get_metadata()[
            CredentialManagement.RESULT.EXISTING_CRED_COUNT
        ]
        if before != baseline:
            raise SystemExit("resident credential count changed before creation")

        client_data_hash = os.urandom(32)
        make_token = pin_token(
            client_pin,
            pin,
            ClientPin.PERMISSION.MAKE_CREDENTIAL,
            RP_ID,
        )
        pin_uv_param = client_pin.protocol.authenticate(make_token, client_data_hash)
        response = ctap.make_credential(
            client_data_hash,
            {"id": RP_ID, "name": "Salpa resident probe"},
            {
                "id": state[K_USER_ID],
                "name": "resident-probe",
                "displayName": "Salpa resident probe",
            },
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=client_pin.protocol.VERSION,
            on_keepalive=user_presence_notice(),
        )
        credential = response.auth_data.credential_data
        if credential is None or credential.public_key.get(3) != -7:
            raise SystemExit("authenticator did not return an ES256 credential")
        if not response.auth_data.is_user_present():
            raise SystemExit("resident credential lacks the user-presence flag")
        if not response.auth_data.is_user_verified():
            raise SystemExit("resident credential lacks the user-verification flag")

        state[K_CREDENTIAL_ID] = credential.credential_id
        state[K_PUBLIC_KEY] = dict(credential.public_key)
        replace_state(state_path, state)
        state[K_ATTESTATION_CERT_HASH] = verify_basic_attestation(
            response, client_data_hash
        )
        replace_state(state_path, state)

        management_token = pin_token(
            client_pin, pin, ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
        management = CredentialManagement(
            ctap, client_pin.protocol, management_token
        )
        after = management.get_metadata()[
            CredentialManagement.RESULT.EXISTING_CRED_COUNT
        ]
        if after != baseline + 1:
            raise SystemExit("resident credential count did not increase by one")
    finally:
        device.close()
    print("passed: PIN-verified discoverable ES256 credential created and attested")


def assert_discoverable(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    if not isinstance(state.get(K_CREDENTIAL_ID), bytes):
        raise SystemExit("resident credential has not been created")
    if not isinstance(state.get(K_PUBLIC_KEY), dict):
        raise SystemExit("resident credential public key is missing")

    device = open_device(vid, pid)
    try:
        ctap = Ctap2(device)
        client_pin = pin_client(ctap)
        client_data_hash = os.urandom(32)
        token = pin_token(
            client_pin,
            state[K_PIN],
            ClientPin.PERMISSION.GET_ASSERTION,
            RP_ID,
        )
        pin_uv_param = client_pin.protocol.authenticate(token, client_data_hash)
        assertion = ctap.get_assertion(
            RP_ID,
            client_data_hash,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=client_pin.protocol.VERSION,
            on_keepalive=user_presence_notice(),
        )
        if assertion.credential.get("id") != state[K_CREDENTIAL_ID]:
            raise SystemExit("discoverable assertion returned a different credential")
        if assertion.user is None or assertion.user.get("id") != state[K_USER_ID]:
            raise SystemExit("discoverable assertion returned different user metadata")
        if not assertion.auth_data.is_user_present():
            raise SystemExit("discoverable assertion lacks the user-presence flag")
        if not assertion.auth_data.is_user_verified():
            raise SystemExit("discoverable assertion lacks the user-verification flag")
        assertion.verify(client_data_hash, CoseKey.parse(state[K_PUBLIC_KEY]))
    finally:
        device.close()
    print("passed: allow-list-free assertion matched and its ES256 signature verified")


def manage_delete(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    credential_id = state.get(K_CREDENTIAL_ID)
    baseline = state.get(K_BASELINE_CREDENTIALS)
    if not isinstance(credential_id, bytes) or not isinstance(baseline, int):
        raise SystemExit("resident credential metadata is incomplete")

    device = open_device(vid, pid)
    try:
        ctap = Ctap2(device)
        client_pin = pin_client(ctap)
        token = pin_token(
            client_pin, state[K_PIN], ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
        management = CredentialManagement(ctap, client_pin.protocol, token)
        before = management.get_metadata()[
            CredentialManagement.RESULT.EXISTING_CRED_COUNT
        ]
        if before != baseline + 1:
            raise SystemExit("unexpected resident credential count before deletion")

        rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
        rps = management.enumerate_rps()
        if sum(
            entry.get(CredentialManagement.RESULT.RP_ID_HASH) == rp_id_hash
            for entry in rps
        ) != 1:
            raise SystemExit("credential management did not enumerate the test RP")
        credentials = management.enumerate_creds(rp_id_hash)
        matches = [
            entry
            for entry in credentials
            if entry[CredentialManagement.RESULT.CREDENTIAL_ID].get("id")
            == credential_id
        ]
        if len(matches) != 1:
            raise SystemExit("credential management did not enumerate the test credential")
        management.delete_cred(
            matches[0][CredentialManagement.RESULT.CREDENTIAL_ID]
        )

        after = management.get_metadata()[
            CredentialManagement.RESULT.EXISTING_CRED_COUNT
        ]
        if after != baseline:
            raise SystemExit("resident credential count did not return to baseline")
        if any(
            entry[CredentialManagement.RESULT.CREDENTIAL_ID].get("id")
            == credential_id
            for entry in management.enumerate_creds(rp_id_hash)
        ):
            raise SystemExit("deleted resident credential was still enumerated")
        state[K_CREDENTIAL_DELETED] = True
        replace_state(state_path, state)
    finally:
        device.close()
    print("passed: credential management enumerated and deleted only the test credential")


def reset_authenticator(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    if state.get(K_CREDENTIAL_DELETED) is not True:
        raise SystemExit("credential-management deletion must pass before reset")

    device = wait_for_reset_reenumeration(vid, pid)
    try:
        ctap = Ctap2(device)
        if ctap.info.options.get("clientPin") is not True:
            raise SystemExit("temporary PIN is not configured before reset")
        ctap.reset(on_keepalive=user_presence_notice())
        info = ctap.get_info()
        if info.options.get("clientPin") is not False:
            raise SystemExit("authenticatorReset did not clear the PIN")
        if bytes(info.aaguid) != state[K_AAGUID]:
            raise SystemExit("authenticatorReset changed the development AAGUID")
        retries, _ = pin_client(ctap).get_pin_retries()
        if retries != state[K_INITIAL_RETRIES]:
            raise SystemExit("authenticatorReset did not restore PIN retries")
        state[K_RESET_VERIFIED] = True
        replace_state(state_path, state)
    finally:
        device.close()
    print("passed: authenticatorReset cleared PIN state and preserved the AAGUID")


def attest_after_reset(vid: int, pid: int, state_path: Path) -> None:
    state = read_state(state_path)
    if state.get(K_RESET_VERIFIED) is not True:
        raise SystemExit("authenticatorReset verification must pass first")
    expected_cert_hash = state.get(K_ATTESTATION_CERT_HASH)
    if not isinstance(expected_cert_hash, bytes):
        raise SystemExit("pre-reset attestation evidence is missing")

    device = open_device(vid, pid)
    try:
        ctap = Ctap2(device)
        if ctap.info.options.get("clientPin") is not False:
            raise SystemExit("PIN unexpectedly reappeared after reset")
        if bytes(ctap.info.aaguid) != state[K_AAGUID]:
            raise SystemExit("post-reset AAGUID does not match")
        client_data_hash = os.urandom(32)
        response = ctap.make_credential(
            client_data_hash,
            {"id": "reset.rissokey.invalid", "name": "Salpa reset probe"},
            {
                "id": os.urandom(32),
                "name": "reset-probe",
                "displayName": "Salpa reset probe",
            },
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
            on_keepalive=user_presence_notice(),
        )
        if verify_basic_attestation(response, client_data_hash) != expected_cert_hash:
            raise SystemExit("development attestation certificate changed across reset")
    finally:
        device.close()

    state_path.unlink()
    sync_parent(state_path)
    print(
        "passed: the same development certificate signed after reset; "
        "protected host state deleted"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=(
            "set-pin",
            "test-retries",
            "create-resident",
            "assert-discoverable",
            "manage-delete",
            "reset",
            "attest-after-reset",
        ),
    )
    parser.add_argument("vid", type=usb_id)
    parser.add_argument("pid", type=usb_id)
    parser.add_argument("state", type=Path)
    args = parser.parse_args()

    installed_version = version("fido2")
    if installed_version != FIDO2_VERSION:
        raise SystemExit(
            f"this probe requires python-fido2 {FIDO2_VERSION}, "
            f"found {installed_version}"
        )

    actions = {
        "set-pin": set_pin,
        "test-retries": test_retries,
        "create-resident": create_resident,
        "assert-discoverable": assert_discoverable,
        "manage-delete": manage_delete,
        "reset": reset_authenticator,
        "attest-after-reset": attest_after_reset,
    }
    actions[args.mode](args.vid, args.pid, args.state)


if __name__ == "__main__":
    main()
