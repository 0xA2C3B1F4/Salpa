# CTAPHID and GetInfo bring-up

## Implemented boundary

`src/ctaphid.rs` is a fixed-memory CTAPHID transport engine built against the
FIDO Alliance packet format. It accepts fixed 64-byte HID reports, assembles
initial and continuation packets, and fragments responses without allocation.
The implementation uses 57 payload bytes in an initial packet and 59 in each
continuation packet, with a current message limit of 1,024 bytes.

The engine implements these transport behaviors:

- broadcast and allocated-channel `CTAPHID_INIT`, including resynchronization
- single- and multi-packet `CTAPHID_PING`
- `CTAPHID_CBOR` request delivery and response framing
- same-channel `CTAPHID_CANCEL`, surfaced to the integrated Trussed interrupt;
  the original CBOR request remains pending until it returns
  `CTAP2_ERR_KEEPALIVE_CANCEL`
- application-triggered `CTAPHID_KEEPALIVE`
- `CTAPHID_ERROR` for invalid commands, lengths, sequences, channels, receive
  timeout, and channel contention
- one active transaction plus a fixed queue for immediate errors on competing
  channels

Unexpected continuation packets are ignored. A fragmented receive is abandoned
after 550 ms without a valid packet. `MSG`, `LOCK`, and `WINK` are not
implemented and receive `ERR_INVALID_CMD`; the INIT capability byte advertises
CBOR and the absence of MSG accordingly.

The normative protocol reference is the FIDO Alliance
[CTAP 2.1 specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html).
The pinned SoloKeys
[`usbd-ctaphid` revision](https://github.com/solokeys/usbd-ctaphid/tree/dd036376536df970310cf9b6406fb165c881aef1)
was reviewed for state-machine behavior, but it is not linked: it uses
`usb-device` 0.2 while the selected ESP HAL boundary uses 0.3. The patched
dispatch graph now compiles on ESP32-S2, but replacing the already validated
local transport has not been justified.

## Deliberately narrow flashed CTAP2 response

`src/get_info.rs` parses requests and serializes responses with the pinned
SoloKeys `ctap-types` revision. Only `authenticatorGetInfo` succeeds. Other CTAP2
operations return the upstream `CTAP2_ERR_INVALID_COMMAND` status, so this
firmware cannot create or use credentials and does not claim that it can.

That description applies to the physically tested bring-up image from commit
`5746457` and remains the fallback when the integrated S2 FIDO platform is not
selected. The S2 `fido-stack` path now also has physical credential, persistence,
PIN, cancellation, and reset evidence; see `platform-services.md`.

The development response advertises:

- `FIDO_2_0`
- USB transport
- `maxMsgSize` 1,024
- user presence required (`up: true`)
- no resident keys, platform-authenticator role, PIN, algorithms, extensions,
  credential management, or user verification
- public development AAGUID `989e2cc2-05df-4e64-8068-22683886e8b`

The AAGUID is not a private key. It is the project bring-up identity also bound
into the generated development attestation certificate. The certificate and
private key have been provisioned on the development board and verified through
physical attestation before and after `authenticatorReset`.

## Reproducible checks

Run the pure transport tests on the host without creating a repository build
tree:

```sh
rustc --edition=2024 --test src/ctaphid.rs \
  -o "$TMPDIR/rissokey-ctaphid-tests"
"$TMPDIR/rissokey-ctaphid-tests"
```

Build the current WEMOS S2 Mini target with the external Espressif toolchain
and build directory:

```sh
SALPA_MCU=esp32s2 \
SALPA_USB_VID="$SALPA_ASSIGNED_USB_VID" \
SALPA_USB_PID="$SALPA_ASSIGNED_USB_PID" \
SALPA_USB_SERIAL="$SALPA_DEVICE_SERIAL" \
./tools/cargo-esp build --locked --release --no-default-features \
  --features mcu-esp32s2,ctaphid-bringup
```

After an explicitly authorized physical flash, validate INIT, an 80-byte
fragmented PING, and GetInfo with `python-fido2` 2.2.1:

```sh
python3 -m venv "$TMPDIR/rissokey-fido2-venv"
"$TMPDIR/rissokey-fido2-venv/bin/pip" install 'fido2==2.2.1'
"$TMPDIR/rissokey-fido2-venv/bin/python" tools/fido2-get-info.py \
  "$SALPA_ASSIGNED_USB_VID" "$SALPA_ASSIGNED_USB_PID"
```

Passing these checks proves the USB CTAPHID transport and the narrow GetInfo
response. It does not prove credentials, cryptography, storage, user-presence
hardware, PIN behavior, persistence, browser interoperability, or OpenAI
enrollment.

For the integrated firmware, test cancellation and same-channel
resynchronization without changing credential storage:

```sh
"$TMPDIR/rissokey-fido2-venv/bin/python" \
  tools/fido2-interrupt-probe.py \
  "$SALPA_ASSIGNED_USB_VID" "$SALPA_ASSIGNED_USB_PID"
```

The probe requires `python-fido2` 2.2.1. It uses CTAP2 Selection, which asks
for user presence but does not create a credential. The first check sends
`CTAPHID_CANCEL` after `UP_NEEDED` and requires the original request to return
`KEEPALIVE_CANCEL`. The second sends a same-channel `CTAPHID_INIT` during the
wait and verifies the nonce and unchanged channel ID. Each check finishes with
GetInfo on the same channel.

## Physical ESP32-S2 result

The CTAPHID build from clean source commit `5746457` was flashed to the WEMOS
S2 Mini on 2026-09-03 through its native USB ROM loader. The image used DIO at
40 MHz and retained the device's existing build-time USB serial without printing
it or adding it to Git.

```text
ELF SHA-256: 2647a60790d3c6628ea7f862e43df121839c32984f1327f1bc5fe56e70d4f4d3
Merged image: 197,632 bytes at 0x0
Merged image SHA-256: f7b9f6be8598a25101f2e8e6736e3b299e5e6de422068d41d7a6ef408c87657b
Write span erased: 0x00000000 through 0x00030fff
Flash result: 197,632 bytes written; esptool data hash verified
```

After the watchdog reset, macOS rediscovered one matching FIDO HID device with
64-byte input and output reports. `python-fido2` 2.2.1 then completed CTAPHID
INIT, echoed an 80-byte PING across packet boundaries, and decoded
`authenticatorGetInfo`. Four consecutive runs passed:

```text
CTAPHID protocol: 2
Firmware version: 0.1.0
Capabilities: 0x0c
Versions: FIDO_2_0
Options: rk=false, up=true, plat=false
maxMsgSize: 1024
Transports: usb
Extensions, algorithms, and PIN/UV protocols: empty
```

This historical test covered physical CTAPHID and a narrow GetInfo image,
which did not implement credential registration or authentication. See the
[S2 test report](../testing/esp32s2-results.md) for the later integrated results.

## Integrated interrupt result

The full FIDO image from clean commit `54d52a1` was flashed to the same WEMOS
S2 Mini on 2026-09-03. The write stopped below `fido_store` and preserved the
provisioned identity and credentials.

```text
ELF SHA-256: b0f5e99ef9eca38afa3e88aa64cb7494efd61e94128919fd5dea4458fe8ef573
Merged image: 476,448 bytes at 0x0
Merged image SHA-256: 2e6a1b3328f3d4c7becbaae0e9710499ff0fd1a421d6aba75c8c25305b429213
Write span erased: 0x00000000 through 0x00074fff
Flash result: 477,184 bytes written; esptool data hash verified
```

The old image received `CTAPHID_CANCEL` but left the host without the required
CBOR response. The same probe passed after the reflash: `CANCEL` returned
`KEEPALIVE_CANCEL`, same-channel `INIT` echoed its nonce and retained its
allocated channel, and GetInfo succeeded after both interruptions. This closes
the physical cancellation and resynchronization gate for the integrated image.
