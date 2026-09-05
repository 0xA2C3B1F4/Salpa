# ESP platform services

## Implemented boundary

The ESP32-S2 source now supplies the services needed by the pinned
SoloKeys/Trussed authenticator:

- `HardwareRng` owns the ESP HAL true-random source and implements the
  `rand_core` traits used by Trussed. Startup rejects all-zero or repeated
  32-byte blocks as a narrow stuck-source check, not as RNG certification.
- `WemosS2MiniUserInterface` uses the active-high built-in LED on GPIO15.
  Development builds read the active-low BOOT button on GPIO0. The protected
  feature reads an external active-low button on GPIO16. A request accepts one
  fresh, debounced press. A held or old press cannot approve a later request.
- `FidoFlashStorage` confines littlefs reads, writes, and erases to the
  `fido_store` partition at `0x3e0000`, size `0x20000` (128 KiB), on the WEMOS
  S2 Mini's 4 MiB flash. Development builds use the existing raw-flash backend.
  The ESP32-S2 `release-flash-encryption` feature selects a separate backend
  with decrypted DROM reads and 32-byte ROM-encrypted writes.
- Internal and external Trussed locations intentionally share that persistent
  filesystem. Volatile data uses a separate 32 KiB RAM filesystem.
- `FidoDispatch` routes the filesystem-info and HKDF extensions required by the
  upstream authenticator through `trussed-staging`.
- The local CTAPHID CBOR event calls the pinned upstream
  `fido-authenticator::Authenticator<Conforming, _>` rather than the narrow
  GetInfo-only dispatcher.
- While Trussed waits for physical presence, the UI hook continues polling USB,
  queues an `UP_NEEDED` KEEPALIVE every 100 ms, and maps CANCEL or channel
  resynchronization to the Trussed interrupt flag.

The complete ESP32-S2 USB/FIDO release ELF links with `maxMsgSize` 1,024. Its
measured allocatable sections are:

```text
text: 386,999 bytes
data: 2,760 bytes
bss: 168,248 bytes
```

The BSS total includes the linker's 159,324-byte `.stack` reservation. These
numbers are compile evidence, not runtime memory or credential evidence.

The development provisioner also passes its release link gate. Its measured
allocatable sections are 229,663 bytes text, 2,008 bytes data, and 169,000 bytes
BSS, including a 164,176-byte stack reservation. These numbers do not prove a
physical flash write or successful provisioning.

## Persistent-storage safety

`partitions.csv` keeps the ESP32-S2 `nvs` and `phy_init` entries, and reserves
the final 128 KiB of the 4 MiB flash for `fido_store`. `build.rs` rejects a
changed name, type, offset, or size, and the Espressif runner is configured to
flash the same table.

Normal firmware does only these persistent-storage operations at startup:

1. mount `fido_store`;
2. verify `/.rissokey-storage-format` contains
   `rissokey-fido-store-v1`;
3. verify `fido/sec/00` is a sensitive P-256 key and `fido/x5c/00` contains the
   RissoKey development AAGUID;
4. stop on a mount, read, version, key, certificate, or AAGUID error.

It never formats persistent storage. The volatile RAM filesystem is formatted
on every boot by design.

The release flash-encryption backend requires the
`signed-ab-encrypted` partition profile and active flash encryption at runtime.
It refuses to mount when encryption is disabled. Existing unencrypted stores
are not migrated or formatted automatically. See
[`flash-encryption-storage.md`](flash-encryption-storage.md) for its mappings,
build contract, and unpassed physical gate.

Formatting is confined to the separately selected `provision-storage` binary.
That image must observe the BOOT button released after startup and then held
continuously for five seconds within a 30-second window. It formats an empty
filesystem, writes the version marker, verifies it, and stops. Merely building
this binary is not authorization to flash it or erase a device.

Compile it explicitly with:

```sh
RISSO_KEY_MCU=esp32s2 \
RISSO_KEY_PROVISIONING_ACK=ERASE_FIDO_STORE \
./tools/cargo-esp build --locked --release --bin provision-storage \
  --no-default-features --features mcu-esp32s2,storage-provisioning
```

The storage-only image intentionally leaves no attestation identity, so the
integrated authenticator will refuse to start after it. It is a low-level erase
and filesystem bootstrap tool, not the normal development provisioning path.

### Host fault-injection result

Normal firmware now calls the format-free `mount_existing` function for the
persistent partition. That function mounts an existing filesystem and checks
its version marker. It returns every mount, read, and version error without a
repair or format attempt. The only `Filesystem::format` call in the normal
binary targets `VolatileStorage`; persistent format calls remain confined to
`provision-storage` and `provision-development`.

`tests/storage-faults` runs that production entry point with `littlefs2` 0.8.1
and a software NOR device matching the 128 KiB partition geometry. Eight tests
passed on the macOS arm64 host:

- normal startup mounted and checked the marker without a program or erase;
- unformatted, all-zero, wrong-version, and dual-superblock corruption failed
  without changing the image;
- one corrupt superblock recovered without a startup write;
- an I/O fault at every startup read returned an error without mutation;
- every flash operation in version-marker creation was interrupted at zero,
  half, and all bytes, after which normal startup never formatted the image;
- a record update was positioned at a littlefs garbage-collection boundary,
  then every program and erase was interrupted at zero, half, and all bytes;
  remount always returned the complete old or new record.

Run the pinned standalone harness with:

```sh
./tools/test-storage-faults
```

Release Clippy with warnings denied and full release linking also passed for
the ESP32-S2 and ESP32-S3 FIDO builds after the startup refactor. The host NOR
model exercises the real littlefs C implementation, but not ESP flash timing or
brownout behavior. The physical power-cut result is recorded separately below.

### Physical power-cut result

On 2026-09-03, a second disposable WEMOS S2 Mini ran the separate
`storage-powercut-test` image against the provisioned 128 KiB `fido_store`.
The image has no normal USB authenticator path. Building it requires both the
`physical-storage-fault-test` feature and
`RISSO_KEY_PHYSICAL_FAULT_TEST_ACK=INTERRUPT_FIDO_STORE`. It also requires the
BOOT button to be observed released and then held continuously for five
seconds before either test phase can modify storage. The image contains no
formatting path.

The program phase first committed a stage marker and a complete old test
record. Its storage wrapper then programmed the first aligned half of a
littlefs driver write, illuminated the LED, and paused before programming the
rest. USB power was removed while paused. After reconnect, littlefs mounted,
the version marker and development attestation validated, and the record was a
complete old or new value.

After a second fresh five-second hold, the erase phase repeatedly replaced the
same non-secret test record until littlefs requested an erase. The wrapper
completed one 4,096-byte sector erase, illuminated the LED, and paused before
returning completion to littlefs. Power was removed again. The next boot
mounted and validated the store, found a complete old or new record, removed
both test files, and signalled success with a fast LED pattern.

The flashed test application image was 106,352 bytes with SHA-256
`cff7b8a28ba1b0fa6343cc149558e5c93e12e8d4aae9a1bd9ac6eb3ad472598d`.
Its app write ended at `0x29f70`, below `fido_store` at `0x3e0000`. The earlier
normal FIDO image was then restored only to the app partition through exclusive
end address `0x71a00`, verified against flash, and started. CTAPHID INIT, an
80-byte fragmented PING, full GetInfo capability checks, and the unchanged
development AAGUID all passed.

This proves filesystem recovery on the physical ESP flash after power loss
between lower-level mutations. It does not characterize voltage thresholds or
cell state when power collapses while the flash controller is still executing
a program or erase command. That test needs controlled power-cut hardware.

## Development attestation provisioning

`tools/generate-dev-attestation.py` generates a new P-256 development key and a
self-signed attestation certificate. The certificate has `CA:FALSE`, the
required `OU=Authenticator Attestation`, and AAGUID extension
`1.3.6.1.4.1.45724.1.1.4` containing
`989e2cc2-05df-4e64-8068-22683886e8b`. The script verifies the certificate
signature, key match, and extension before writing key or certificate files. It
requires the Python `cryptography` package.

Create the material outside the repository in a new mode-`0700` directory:

```sh
python3 tools/generate-dev-attestation.py \
  "$TMPDIR/rissokey-development-attestation"
```

The raw private key is mode `0600`. Protect it and the build output that embeds
it. Neither belongs in Git, logs, chat, or a shared artifact store.

Build the separate provisioning image by passing only file paths through the
environment:

```sh
RISSO_KEY_MCU=esp32s2 \
RISSO_KEY_PROVISIONING_ACK=ERASE_FIDO_STORE \
RISSO_KEY_DEV_ATTESTATION_KEY="$TMPDIR/rissokey-development-attestation/attestation-key.raw" \
RISSO_KEY_DEV_ATTESTATION_CERT="$TMPDIR/rissokey-development-attestation/attestation-cert.der" \
./tools/cargo-esp build --locked --release --bin provision-development \
  --no-default-features --features mcu-esp32s2,development-provisioning
```

`provision-development` validates the private-scalar range and certificate
AAGUID before arming. It then requires the BOOT button to be observed released
and held continuously for five seconds within 30 seconds. Only after that
gesture does it format `fido_store`, use Trussed to validate and import the
private scalar again, install key ID `00` and certificate ID `00`, and verify
the mounted result. Building it is not device write authorization.

The development reset policy has two levels:

- CTAP `authenticatorReset` is the normal credential/PIN reset. The pinned
  implementation accepts it only in its post-boot reset window and still asks
  for fresh physical presence. It deletes generated keys and FIDO state while
  preserving the special attestation key `00`, certificate `00`, filesystem
  version marker, and AAGUID.
- Reflashing and confirming `provision-development` is the full-store recovery
  path. It erases every credential and reinstalls the supplied development
  identity. No normal-firmware path formats or silently repairs the store.

Stores that already contain a valid `persistent-state.cbor` remain compatible
and do not need the initialization marker. A store formatted by an older
provisioner but never initialized has neither the state file nor the marker;
normal firmware therefore rejects it until the current destructive provisioner
is run. A corrupt or unreadable state also cannot be repaired with CTAP
`authenticatorReset`, because command dispatch fails before reset handling.
Recovery is intentionally explicit and destructive: rerun the applicable
provisioning image, then flash normal firmware again.

## Reproducible compile checks

The full S2 path requires non-production build-time USB identity values in the
environment:

```sh
RISSO_KEY_MCU=esp32s2 \
RISSO_KEY_USB_VID="$RISSO_KEY_ASSIGNED_USB_VID" \
RISSO_KEY_USB_PID="$RISSO_KEY_ASSIGNED_USB_PID" \
RISSO_KEY_USB_SERIAL="$RISSO_KEY_DEVICE_SERIAL" \
./tools/cargo-esp clippy --locked --release --bin rissokey \
  --no-default-features --features mcu-esp32s2,ctaphid-bringup,fido-stack \
  -- -D warnings
```

Replace `clippy ... -- -D warnings` with `build` for the release link gate.
The `tools/cargo-esp` wrapper passes `-mlongcalls` to C dependencies; this is
needed for littlefs calls in the Xtensa memory layout.

The pure state machines can be tested without a repository build directory:

```sh
rustc --edition=2024 --test src/platform/user_presence.rs \
  -o "$TMPDIR/rissokey-user-presence-tests"
"$TMPDIR/rissokey-user-presence-tests"

rustc --edition=2024 --test src/platform/rng_health.rs \
  -o "$TMPDIR/rissokey-rng-health-tests"
"$TMPDIR/rissokey-rng-health-tests"

rustc --edition=2024 --test src/platform/storage_layout.rs \
  -o "$TMPDIR/rissokey-storage-layout-tests"
"$TMPDIR/rissokey-storage-layout-tests"

rustc --edition=2024 --test src/platform/provisioning.rs \
  -o "$TMPDIR/rissokey-provisioning-tests"
"$TMPDIR/rissokey-provisioning-tests"

rustc --edition=2024 --test src/identity.rs \
  -o "$TMPDIR/rissokey-identity-tests"
"$TMPDIR/rissokey-identity-tests"
```

The current counts are five user-presence tests, five development identity
tests, and three tests each for RNG sanity, partition ranges, and the
destructive provisioning gesture.

Run the physical credential-persistence probe only in a protected temporary
directory. `create` and `assert` each require a fresh BOOT-button press:

```sh
install -d -m 700 "$TMPDIR/rissokey-persistence"
"$TMPDIR/rissokey-fido2-venv/bin/python" \
  tools/fido2-credential-persistence.py create \
  "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" \
  "$TMPDIR/rissokey-persistence/state.cbor"

# Disconnect and reconnect the authenticator before the second command.
"$TMPDIR/rissokey-fido2-venv/bin/python" \
  tools/fido2-credential-persistence.py assert \
  "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" \
  "$TMPDIR/rissokey-persistence/state.cbor"
```

The state file contains a credential ID and public key. Keep its mode at
`0600`, do not add it to Git, and delete it after the test.

Run the destructive PIN and discoverable-credential probe only on a development
authenticator with no user credentials worth keeping. The final reset removes
every user credential and the PIN. The tool keeps its random temporary PIN and
test identifiers in a mode-`0600` file and never prints their values:

```sh
install -d -m 700 "$TMPDIR/rissokey-pin-resident"
state="$TMPDIR/rissokey-pin-resident/state.cbor"
probe() {
  "$TMPDIR/rissokey-fido2-venv/bin/python" tools/fido2-pin-resident-probe.py "$@"
}

probe set-pin "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
probe test-retries "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
probe create-resident "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
probe assert-discoverable "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
probe manage-delete "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
probe reset "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
probe attest-after-reset "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID" "$state"
```

Press BOOT when `create-resident`, `assert-discoverable`, and
`attest-after-reset` request presence. The `reset` step waits for a physical
RESET press, sends CTAP `authenticatorReset` immediately after USB
re-enumeration, and then requests BOOT. The last step compares the pre-reset and
post-reset attestation certificate hashes, verifies the signature, and deletes
the protected state file. It creates no resident credential.

## Physical ESP32-S2 result (2026-09-03)

The integrated image was provisioned and tested on the WEMOS S2 Mini over its
native USB connector. A two-entry partition table containing only `factory`
and `fido_store` did not boot. Replacing only that table with the earlier
`nvs`, `phy_init`, and `factory` layout made the same diagnostic application
boot. The fixed table therefore retains `nvs` and `phy_init`, shrinks
`factory`, and appends `fido_store` at `0x3e0000`.

With the fixed table, the normal image enumerated as FIDO HID and returned the
development AAGUID, `maxMsgSize` 1,024, ES256 and EdDSA algorithms, and the
expected user-presence, resident-key, and credential-management options.
`python-fido2` then completed an ES256 MakeCredential operation after a fresh
BOOT-button press. A second fresh press completed GetAssertion, and the host
verified the assertion signature against the newly returned credential public
key. After a plain MCU reset, the same credential completed another assertion
and signature verification. No credential identifier, key material, PIN, or
raw packet log was retained in the repository.

The first normal image had the GPIO15 LED polarity inverted: it illuminated at
idle and went dark while the authenticator reported `UP_NEEDED`. The WEMOS
S2 Mini v1.0.0 schematic shows GPIO15 driving the LED through a series resistor
to ground, so commit `85054b3` treats it as active high. After reflashing that
commit, the LED remained dark at idle, illuminated during `UP_NEEDED`, and
returned to dark after both a successful BOOT-button confirmation and an
approximately 30-second timeout. The successful check used CTAP2 Selection and
did not create a credential. The unanswered request returned
`USER_ACTION_TIMEOUT` without approving a later request.

The first physical `CANCEL` probe exposed a transport bug: CTAPHID discarded
the original CBOR request before Trussed returned `KEEPALIVE_CANCEL`, so the
host received no final response. Commit `54d52a1` keeps that request until the
authenticator reply is ready and signals the interrupt directly from the
cancel event. After reflashing, `tools/fido2-interrupt-probe.py` proved both
interrupt paths with CTAP2 Selection. `CANCEL` returned `KEEPALIVE_CANCEL`, and
a same-channel `INIT` returned the original nonce and channel ID. GetInfo then
succeeded on the same channel after each interruption. Neither path created or
changed a credential.

Physical disconnect persistence was tested with
`tools/fido2-credential-persistence.py`. The probe created a non-resident ES256
credential after fresh user presence and stored only its credential ID and
public key in a mode-`0600` scratch file. The host verified an assertion before
disconnect. After removing the USB cable for at least five seconds and
reconnecting it, macOS enumerated the authenticator again. A new BOOT-button
confirmation produced an assertion whose signature verified with the saved
public key. The scratch state was then deleted without printing or committing
the credential ID.

`tools/fido2-pin-resident-probe.py` then configured a random temporary PIN. One
intentional invalid attempt changed the retry count from 8 to 7, and a valid
PIN token restored it to 8. After fresh user presence, the authenticator
created a PIN-verified discoverable ES256 credential with both UP and UV flags.
An allow-list-free assertion returned the matching credential and user, and
its signature verified against the creation response. Credential management
enumerated the exact test RP and credential, deleted only that credential, and
returned the resident count to its original value.

The probe detected a physical RESET through USB re-enumeration and sent
`authenticatorReset` within the post-boot window. A BOOT confirmation completed
the reset. GetInfo then reported no configured PIN, the retry count was 8, and
the development AAGUID was unchanged. A final non-resident MakeCredential
operation produced a valid signature from the same development attestation
certificate seen before reset. The probe discarded that credential and
deleted its protected host state.

### Safari WebAuthn result

Safari 26.5.2 build 21624.2.5.11.8 on macOS 26.5.2 build 25F84 completed an
ES256 registration and authentication through WebAuthn.io. The accepted test
used these registration settings:

- authenticator attachment `cross-platform`;
- registration and authentication hint `security-key`;
- ES256 as the only public-key algorithm;
- discoverable credential `discouraged`;
- user verification `preferred`;
- attestation `none`.

The LED illuminated and a fresh BOOT press approved both registration and
authentication. WebAuthn.io then reported `You're logged in!` and described
the credential as device-bound with transport `usb`. The site reported an all-
zero AAGUID because the ceremony requested no attestation, so this browser test
does not independently validate the provisioned development AAGUID. No
credential identifier was copied into the repository.

An earlier default-settings attempt selected Safari's platform passkey and did
not illuminate the device LED. That result was rejected as hardware evidence.
Forcing cross-platform attachment and the security-key hint prevented the
platform passkey from satisfying the accepted test.

## Open gates

### OpenAI interoperability result

Chromium 147.0.7691.0 on macOS 26.5.2 build 25F84 enrolled the physical
RissoKey through ChatGPT's ordinary **Security keys & passkeys** settings. The
platform required a new security-key PIN during enrollment. After completion,
the account listed a new generic `Passkey` dated September 3, 2026 alongside
the pre-existing platform passkey; the existing fallback was not removed.

A separate Chromium Incognito session then entered the account identifier and
authenticated with the enrolled RissoKey. The session reached the signed-in
ChatGPT account, proving later OpenAI authentication rather than only successful
enrollment. Advanced Account Security was deliberately left disabled for this
test. No account identifier, PIN, credential ID, one-time token, private key, or
raw WebAuthn packet was recorded.

Safari did not reach WebAuthn in the initial OpenAI enrollment page. Its
enrollment-start request omitted a required page token after Safari reported
blocking query-parameter access, so OpenAI returned HTTP 400 before USB or CTAP
was invoked. Disabling the site's Safari content blocker did not change that
behavior, and the setting was restored. After Chromium enrolled the key, a
fresh Safari sign-in successfully authenticated with the same RissoKey and
reached the signed-in ChatGPT account. The Safari enrollment failure was
therefore outside the RissoKey transport and authenticator path; Safari's
OpenAI authentication path is proven separately.

Electrical behavior during a flash-controller program or erase command remains
open. The completed physical power-cut test covers recovery between lower-level
flash mutations.
