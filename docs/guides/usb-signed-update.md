# Signed update over USB

Users install an application already signed by their firmware publisher.
They need neither private firmware keys nor the macOS signing helper for
installation or ordinary login. Start with the
[user update steps](installing-and-updating.md#working-device-signed-usb-update).
Publishers and builders managing their own keys use the separate
[firmware signing and maintainer key-management guide](key-management.md).

RissoKey carries its ESP32-S2 update protocol in CTAPHID vendor command
`0x51`. The runtime receives one signed ESP application image, writes only the
inactive A/B slot, reads it back, verifies it, and changes `otadata` last. The
implementation does not enter the ESP ROM downloader and does not contain
Nordic or LPC55 flash code.

The development path passed its physical ESP32-S2 gate. The device completed a
signed update, preserved the previous slot through a power cut, rejected a
wrong signing key before activation, and rolled back an unconfirmed candidate.
This path does not enable Secure Boot, flash encryption, or any eFuse.

## Authorization and trust boundary

`BEGIN` requires a released button followed by a fresh debounced press within
15 seconds. A button held before the request does not approve it. The device
keeps the CTAPHID operation alive with `UP_NEEDED` messages and accepts
CTAPHID Cancel while waiting. Erase cannot start before approval.

Same-channel `INIT` resynchronization, including a malformed `INIT`, also
cancels the approval wait. A discarded request receives no stale update reply;
the transport's `INIT` or error reply is preserved and a new `BEGIN` can follow.

The build embeds only the SHA-256 digest of the trusted RSA-3072 public key.
The received ESP Secure Boot V2 signature block supplies the public key and
signature. The runtime checks the signature-block CRC, the embedded key digest,
the signed image digest, and RSA-PSS with the ESP32-S2 ROM verifier. The private
key never belongs in firmware, a package, or Git.

The host also compares the application `secure_version` with the running
device, but this is only an early error. The device independently enforces the
same anti-rollback check before erase and after readback. The version string
and complete-file SHA-256 sent by the host must match the read-back image.

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
  --update-key-digest "$RISSO_KEY_TRUSTED_PUBLIC_KEY_DIGEST" \
  --secure-version "$RISSO_KEY_SECURE_VERSION" \
  --build-dir "$RISSO_KEY_AB_BUILD_ROOT/success"
```

The protected runtime builder accepts both arguments. `secure_version` is the
monotonic anti-rollback value in the ESP application descriptor, not a semantic
version parser. Build the normal runtime with the default `normal` variant and
the deliberate first-boot rollback fixture separately:

```sh
python3 tools/build-protected-app.py \
  --image runtime \
  --runtime-variant rollback-failure \
  --update-key-digest "$RISSO_KEY_TRUSTED_PUBLIC_KEY_DIGEST" \
  --secure-version "$RISSO_KEY_SECURE_VERSION" \
  --build-dir "$RISSO_KEY_PROTECTED_BUILD_ROOT/rollback-failure"
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
python3 -m venv "$TMPDIR/rissokey-usb-ota-venv"
"$TMPDIR/rissokey-usb-ota-venv/bin/pip" install 'fido2==2.2.1'
"$TMPDIR/rissokey-usb-ota-venv/bin/python" tools/rissokey-usb-ota.py \
  "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" \
  "$RISSO_KEY_SIGNED_UPDATE_IMAGE"
```

The CLI prints device and image versions, the complete image hash, and progress
for erase, transfer, and verification. It asks for the physical button when the
device returns a user-presence keepalive. After activation, disconnect and
reconnect the device to boot the candidate.

## Verification and remaining gate

Pure Rust regressions cover inactive-slot-only mutation, activation-last,
required physical presence, out-of-order chunks, readback hash failure, invalid
RSA, interrupted transfer, secure-version rollback, pending-candidate refusal,
and bootloader rollback selection. Python tests cover strict image and response
parsing, contiguous 992-byte host transfer, activation-last request order, and
host-side rollback refusal. Both normal and release flash-encryption ESP32-S2
feature sets compile and link.

On 2026-09-05, the update-audit fixes passed 70 main-library host tests, eight
storage-fault tests, eight Python tests, and the persistent-state suite. The
latter ran nine authenticator tests plus four shared reply-completion tests imported from
the production source. Its new regression uses real authenticator responses
for missing and corrupt storage, and a successful initialized GetInfo. The
same completion module is called by `main.rs`; it separates dispatch success,
CTAP status, and transport acceptance, and clears each completed response.
An interrupted successful GetInfo is also rejected for confirmation. The
transport regressions cover approval-wait INIT, malformed INIT, valid CANCEL,
and malformed or unrelated CANCEL. CI now runs the persistent-state suite.

Both normal and deliberate rollback-failure protected runtimes compiled and
linked for `xtensa-esp32s2-none-elf` with secure version 3. These were local
build checks with a synthetic USB identity, using `tools/cargo-esp build
--locked --offline --release --no-default-features --bin rissokey` and the
protected runtime features from `tools/build-protected-app.py`. The failure
build additionally enabled `signed-ab-failure-test`. Formatting, public-source,
partition-layout, security-profile, and eFuse-plan self-checks also passed.
No device was accessed and no signed installation package was created by
these checks. A subsequent clean-source package rebuild for `0d295e8` passed
its host cryptographic checks; see the
[continuation evidence](../evidence/protected-preflight-esp32s2-0d295e8.json).
The preflight package for `fe17f88` predates these fixes. The replacement
initial ciphertext set has since passed physical installation and readback,
followed by the explicitly authorized Secure Boot V2 stage. See the
[stage evidence](../evidence/secure-boot-v2-esp32s2-0d295e8.json). Subsequent encrypted
storage, owner-authorized replacement attestation import, normal FIDO, and
credential persistence after a USB power cycle passed. The first protected
USB update stopped at the missing initial OTA metadata check, before erase.
Fresh metadata initialization then passed complete physical readback while
preserving the credential store. The protected normal USB update passed
on-device verification, activation, FIDO and an existing-credential assertion.
The failure fixture booted as `0.1.1-ab-fail`; the next reset restored `0.1.0`,
and the same credential still signed correctly. Independent encrypted-entry
comparison confirmed sequence 3 `ABORTED`, sequence 2 `VALID`, and selected
slot `ota_1`. All eFuse values and permissions still matched the baseline.
Following explicit authorization, encrypted ROM recovery restored the verified
bootloader, partition table and selected `ota_1` runtime. Every written byte
matched full physical readback. Boot metadata, the encrypted credential store
and all eFuse values and permissions remained unchanged. After the owner reset,
normal FIDO and the same credential's assertion passed again. This completes
these protected-device gates; OpenAI service interoperability is separate. See the
[protected update evidence](../evidence/protected-ota-esp32s2-20260905.json) and
[attestation evidence](../evidence/attestation-import-esp32s2-20260905.json).

The development-device physical result is recorded in
[`docs/evidence/usb-signed-update-esp32s2-0121171.json`](../evidence/usb-signed-update-esp32s2-0121171.json).
The power-cut run stopped after the first 65,536-byte erase transaction. After
power removal and reconnect, version `0.1.0`, secure version 1, and an idle
update session remained available.

The success run transferred and read back all 413,696 bytes, accepted the
pinned signature, and selected inactive `ota_1` only after verification. The
first CTAP response confirmed version `0.1.2-ab-pass`, secure version 2. A
second reconnect kept the same version. A complete wrong-key transfer reached
readback verification but failed signature verification without activation.
The active success version stayed unchanged.

The rollback run transferred and verified the trusted failure fixture, then
selected inactive `ota_0`. Its first boot reported `0.1.1-ab-fail`. Because the
fixture deliberately withheld confirmation, the next reconnect returned to
`0.1.2-ab-pass`, and GetInfo succeeded. A malformed `Begin` and a host attempt
to install secure version 0 were rejected before requesting presence.

That development-device test did not exercise encrypted inactive-slot writes
or decrypted readback. The later protected-device results above record those
separate checks. Neither test report authorizes a new flash or eFuse operation.

## Solo2 reference and license

The protocol was designed after reviewing Solo2 commit
`45311f0b6761187d409ea3e7ea34f896810eb156`. RissoKey uses its CTAPHID vendor
opcode, fresh-presence gate, and host-facing version, hash, and progress ideas.
The RissoKey protocol, ESP32-S2 flash backend, package format, and Python CLI are
new implementations. No Nordic or LPC55 updater or flashing source was copied.

The reviewed Solo2 admin application and CLI are offered under
`Apache-2.0 OR MIT`. RissoKey chooses the compatible MIT option for the design
reference and keeps its own new files under the repository MIT license. No
Solo2 source file is redistributed by this feature.
