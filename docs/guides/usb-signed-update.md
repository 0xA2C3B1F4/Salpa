# Signed update over USB

Users install an application already signed by their firmware publisher.
They need neither private firmware keys nor the macOS signing helper for
installation or ordinary login. Start with the
[user update steps](installing-and-updating.md#working-device-signed-usb-update).
Publishers and builders managing their own keys use the separate
[firmware signing and maintainer key-management guide](key-management.md).

Salpa carries its ESP32-S2 update protocol in CTAPHID vendor command
`0x51`. The runtime receives one signed ESP application image, writes only the
inactive A/B slot, reads it back, verifies it, and changes `otadata` last. The
implementation does not enter the ESP ROM downloader and does not contain
Nordic or LPC55 flash code.

The development path passed its physical ESP32-S2 gate. The device completed a
signed update, preserved the previous slot through a power cut, rejected a
wrong signing key before activation, and rolled back an unconfirmed candidate.
This path does not enable Secure Boot, flash encryption, or any eFuse.

The [final protected S2 trial](../testing/esp32s2-final-hardening.md) also passed
signed USB updates and failed-candidate fallback after ROM download was closed.
ROM closure removes low-level recovery; this updater still requires a working
application and boot chain. The macOS host tools use a continuously scheduled
HID receiver with python-fido2 2.2.1. Ordinary browser login does not use these
tools.

## Authorization and trust boundary

`BEGIN` requires a released button followed by a fresh debounced press within
15 seconds. A button held before the request does not approve it. The device
keeps the CTAPHID operation alive with `UP_NEEDED` messages and accepts
CTAPHID Cancel while waiting. Erase cannot start before approval.

Same-channel `INIT` resynchronization, including a malformed `INIT`, also
cancels the approval wait. A discarded request receives no stale update reply;
the transport's `INIT` or error reply is preserved and a new `BEGIN` can follow.

After a successful `BEGIN`, CTAPHID `Cancel` and `INIT` do not revoke the
approved update session. `Cancel` concerns the current CTAPHID request;
`INIT` resynchronizes the transport. To stop the update itself, send vendor
`Abort` with its session ID. A successful `Abort` discards the session without
further flash writes; a new `BEGIN` needs fresh presence. It does not restore
the overwritten inactive image. After activation, `Abort` is rejected and
cannot undo the boot selection. Reset or power loss also discards the RAM
session. Session IDs are public correlation values, not authentication secrets.

Approval expires after 120 seconds without successful erase, write or
verification progress, or 15 minutes after approval, whichever comes first.
The device owns these deadlines. Status requests, malformed traffic, `INIT`
and `Cancel` do not renew them. A backwards device clock also expires the
session. The existing 15-second physical-approval window is separate.

Expiration leaves a failed RAM session with status `13` (`session-expired`).
Restart the update and approve a new `Begin` with a fresh button press. The
host tool does not retry approval automatically. A running flash operation
finishes safely, but the device checks again before starting later operations
and before activation. Expiry does not restore an overwritten inactive image
or undo an already completed activation. The response layout remains protocol
version 1; older tools reject the unfamiliar nonzero status and must be updated
for the specific recovery message.

These limits are implementation policy, with fake-clock regression coverage.
Their suitability for real slow transfers still requires the
[device acceptance checks](../testing/README.md#usb-update-lifetime-acceptance).

The approved size, hash and version constrain which image can be activated.
They do not prevent an untrusted host from writing incorrect bytes to the
inactive slot before readback rejects them. The running slot stays intact,
but the old fallback image may already have been overwritten.

The build embeds only the SHA-256 digest of the trusted RSA-3072 public key.
The received ESP Secure Boot V2 signature block supplies the public key and
signature. The runtime checks the signature-block CRC, the embedded key digest,
the signed image digest, and RSA-PSS with the ESP32-S2 ROM verifier. The private
key never belongs in firmware, a package, or Git.

The host also compares the application `secure_version` with the running
device, but this is only an early error. The device independently enforces the
same anti-rollback check before erase and after readback. The version string
and complete-file SHA-256 sent by the host must match the read-back image.
After readback, a descriptor below the running security version returns
`Rollback` before the host-claim comparison. A different descriptor version
at or above that floor returns `VersionMismatch`. Neither result activates
the candidate; the signature must also pass before any activation.

## Protocol version 1

All multibyte integers are little-endian. The first request byte selects the
operation:

| Operation | Value | Request after operation |
| --- | ---: | --- |
| Info | `0` | empty |
| Begin | `1` | protocol, size, SHA-256, secure version, version length, version |
| Write | `2` | session ID, offset, up to 992 image bytes |
| Advance | `3` | session ID |
| Status | `4` | empty or session ID |
| Abort | `5` | session ID |

Write offsets must be contiguous and chunks must be 32-byte aligned. Signed
images and the slot are 4 KiB aligned, so the final host chunk is aligned too.
The fixed response contains status, protocol, phase, target slot, session ID,
phase progress, total size, current secure version, and current version.

`Advance` limits one erase or verification transaction to 64 KiB. The host can
therefore report erase, transfer, and readback progress without one long HID
request. A session lives only in RAM. After power loss, the next `Begin` erases
the inactive slot from the start.

## Commit sequence and rollback

The device performs these steps in order:

1. Read the current valid `otadata` selection and choose the other slot.
2. Obtain fresh physical user presence.
3. Erase and write only that inactive slot.
4. Read every received byte back through the raw or decrypted flash path and
   compare the complete SHA-256.
5. Validate the ESP32-S2 descriptor, secure version, image version, signature
   block, pinned public-key digest, signed-image digest, and RSA-PSS signature.
6. Re-read `otadata` and reject the session if the active selection changed.
7. Write the new boot sequence and read it back. This activation is the final
   persistent mutation.

Power loss through step 6 leaves the previous slot selected. The newly selected
image boots as an ESP-IDF `NEW` candidate. It becomes `VALID` only after a
successful CTAP2 status (`0x00`) whose reply was accepted by the transport.
Dispatch success alone is insufficient: persistent-state load failures and
other CTAP errors leave the candidate unconfirmed. This is a boot health check,
not the complete credential-persistence acceptance test.
If confirmation does not happen, the existing bootloader
marks it `ABORTED` and returns to the previous valid slot on reset.

For a flash-encrypted build, the USB package carries the ordinary signed
plaintext application image. The device feeds each 32-byte plaintext block to
the ESP32-S2 encrypted-write ROM function. Verification reads plaintext through
a temporary DROM mapping that is restored after every page. A host must never
send the offset-encrypted package image through this endpoint because that
would encrypt ciphertext a second time.

## Maintainer build preparation

### Fresh encrypted boot metadata

The protected prototype's initial install leaves raw `otadata` erased. With
flash encryption enabled, physical `0xff` bytes decrypt into invalid metadata,
not canonical empty entries. In the pinned ESP-IDF bootloader with rollback
enabled and anti-rollback disabled, this can select the fallback application
without creating its initial sequence entry. The runtime deliberately rejects
an update until a `VALID` entry identifies the current slot. A `BEGIN` failure
at this layout check occurs before any erase or write.

For a fresh device only, after proving normal FIDO and credential persistence
on its verified `ota_0`, prepare an initial seed using
`tools/prepare-initial-otadata.py --erased-otadata-readback "$RAW_OTADATA_READBACK"
--output-dir "$PRIVATE_INITIAL_OTADATA_DIR"`. The tool requires an exact
8192-byte raw-erased snapshot. The local Keychain helper encrypts both sectors
at `0xf000`, with sequence 1 / `VALID` for `ota_0` and a canonical empty second
entry. It verifies the encryption round trip without exporting the flash key.

This command only prepares an artifact. Immediately before an authorized
installation, identify the same device, recheck both raw sectors are erased,
verify the complete installed `ota_0` against its trusted package, and preserve
the encrypted credential store. Verify the entire seed's physical readback
and that credential storage is unchanged. The first update can then select
sequence 2 in the other sector while retaining sequence 1 as its valid fallback.

Never use this seed to overwrite existing valid, pending, aborted or corrupt
OTA history, or include it in a generic recovery install set. Preserve existing
metadata during recovery. Bootloader candidate state transitions and actual
rollback still require physical acceptance.

Both signed A/B application builders require the same public-key digest that
the bootloader package later checks:

```sh
python3 tools/build-signed-ab-app.py \
  --variant success \
  --update-key-digest "$SALPA_TRUSTED_PUBLIC_KEY_DIGEST" \
  --secure-version "$SALPA_SECURE_VERSION" \
  --build-dir "$SALPA_AB_BUILD_ROOT/success"
```

The protected runtime builder accepts both arguments. `secure_version` is the
monotonic anti-rollback value in the ESP application descriptor, not a semantic
version parser. Build the normal runtime with the default `normal` variant and
the deliberate first-boot rollback fixture separately:

```sh
python3 tools/build-protected-app.py \
  --image runtime \
  --runtime-variant rollback-failure \
  --update-key-digest "$SALPA_TRUSTED_PUBLIC_KEY_DIGEST" \
  --secure-version "$SALPA_SECURE_VERSION" \
  --build-dir "$SALPA_PROTECTED_BUILD_ROOT/rollback-failure"
```

The normal and rollback-failure images must use the same secure version. The
protected package records `runtime-usb-signed.bin` and
`rollback-failure-usb-signed.bin` as signed plaintext USB artifacts in addition
to offset-encrypted factory-install images. The failure fixture is test-only
and is excluded from every install and recovery set.

## User: install a signed update

Obtain the normal signed application for your device from its firmware
publisher. The build and Keychain preparation above belong to that publisher;
do not repeat them merely to install an update. Use `python-fido2` 2.2.1 and
the assigned device VID/PID:

```sh
python3 -m venv "$TMPDIR/salpa-usb-ota-venv"
"$TMPDIR/salpa-usb-ota-venv/bin/pip" install 'fido2==2.2.1'
"$TMPDIR/salpa-usb-ota-venv/bin/python" tools/salpa-usb-ota.py \
  "$SALPA_ASSIGNED_USB_VID" "$SALPA_ASSIGNED_USB_PID" \
  "$SALPA_SIGNED_UPDATE_IMAGE"
```

The CLI prints device and image versions, the complete image hash, and progress
for erase, transfer, and verification. It asks for the physical button when the
device returns a user-presence keepalive. After activation, disconnect and
reconnect the device to boot the candidate.

## Verification

Rust regressions cover inactive-slot-only writes, activation after verification,
fresh physical presence, out-of-order chunks, readback hash failure, invalid
signatures, interrupted transfers, secure-version rollback, pending-candidate
refusal and bootloader rollback selection. Python tests cover image and
response parsing, contiguous host transfers and host-side rollback refusal.
Persistent-state tests use real authenticator responses to distinguish dispatch
completion from successful CTAP responses before confirming a new image.

The [testing guide](../testing/README.md) describes the repeatable host and
build checks. These tests use public fixtures and do not establish physical
acceptance of a newly built application.

The [S2 test summary](../testing/esp32s2-results.md) records protected signed
updates, deliberate failed-candidate rollback and encrypted ROM recovery with
an existing credential preserved. Separate unencrypted development tests
covered an untrusted signing key and an interrupted update. Those results
retain their original configuration and do not establish resistance to all
electrical power faults. Browser interoperability is a separate test.

## Solo2 reference and license

The protocol was designed after reviewing Solo2 commit
`45311f0b6761187d409ea3e7ea34f896810eb156`. Salpa uses its CTAPHID vendor
opcode, fresh-presence gate, and host-facing version, hash, and progress ideas.
The Salpa protocol, ESP32-S2 flash backend, package format, and Python CLI are
new implementations. No Nordic or LPC55 updater or flashing source was copied.

The reviewed Solo2 admin application and CLI are offered under
`Apache-2.0 OR MIT`. Salpa chooses the compatible MIT option for the design
reference and keeps its own new files under the repository MIT license. No
Solo2 source file is redistributed by this feature.
