# PIN/UV token lifetime and PIN-state replay

This source review and correction concern the USB ESP32-S2 authenticator.
They do not demonstrate a timing attack or a storage-replay attack against a
physical device. The corrected firmware still needs device acceptance before
final ROM closure. Existing device evidence remains tied to its original
source revision.

## Confirmed findings and correction

The vendored authenticator advertised FIDO 2.0, 2.1 and 2.3 while its PIN-token
usage timers remained TODOs. A valid token could outlive the intended usage
period. HMAC verification and three PIN-hash comparisons used ordinary Rust
slice/array comparisons. Those source properties were confirmed; practical
exploitability and timing leakage were not measured.

The local patch follows the PIN/UV state machine in
[CTAP 2.3, sections 6.5.2 and 6.5.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html):

- USB tokens must first be authorized before 30 seconds and expire at an
  absolute 600 seconds. Successful use never extends that absolute limit.
  No rolling timer or cached user presence is used.
- The clock comes from Trussed uptime. Reversal or a clock error invalidates
  tokens. Expiration is observed at dispatch and before token verification;
  expired keys are deleted from volatile Trussed storage and authorization
  state is cleared. This is command-time enforcement, not a background task
  that wipes RAM exactly when a deadline passes while the device is idle.
- New grants invalidate both protocol versions. PIN change, forced PIN change
  and authenticator reset invalidate tokens and enumeration/ assertion
  continuation state. Reset still requires its existing consent and time gate.
- Permission and RP checks precede marking a grant used. Explicit MC/GA grants
  require an RP ID. Legacy grants bind to the first authenticated RP.
  RP-scoped management cannot enumerate unrelated RPs. Unsupported persistent
  read-only management tokens are rejected rather than silently reinterpreted.
- MC/GA require the token's UV flag. After physical presence, UP and UV state
  and permissions are consumed as specified, retaining only large-blob-write
  permission. An ordinary assertion continues to require fresh physical
  presence; possession of a token does not supply it.
- `subtle` 2.6.1 supplies constant-time HMAC and PIN-hash equality. Wrong HMAC
  lengths are rejected; length is public protocol data. RP names/hashes,
  permission flags, initialization markers and counters retain ordinary
  comparisons. This change does not establish constant-time behavior of the
  whole MCU or protocol implementation.
- A bad credential-management token HMAC does not consume PIN attempts.
  Incorrect PINs still consume persistent attempts, including the three-try
  per-power-cycle block and the eight-try persistent block.

No storage format, operational key, attestation identity or credential data
was changed by this work.

## Provenance and reproducible tests

The pinned base is `fae4a1ec8f55d9abe53a7405faf310ef90f3eb71`.
On 2026-09-06 upstream main was
`e342447aaf2c7fc1b761f4ab78c1ab248857875a`; its
[PIN module](https://github.com/trussed-dev/fido-authenticator/blob/e342447aaf2c7fc1b761f4ab78c1ab248857875a/src/ctap2/pin.rs)
still had the timer TODOs and ordinary HMAC comparison. No equivalent fix was
available in the main revision inspected. This is not a claim that every
upstream branch or unmerged proposal was audited. The patch is locally written
against the existing licensed source and FIDO specification; it does not copy
an implementation from another authenticator project.

Run `tools/test-persistent-state` with the pinned host toolchain. The suite
uses real Trussed virtual crypto/storage and intercepts only the uptime request
with a controlled test clock. Focused tests compile the actual vendored PIN
module; command tests enter the public CTAP dispatcher. All PINs and tokens
are synthetic and RAM-only. The test consent implementation is confined to
this standalone host crate.

Coverage includes both PIN protocols; 29,999/30,000 ms and
599,999/600,000 ms boundaries; backward/failing clocks; invalid and wrong-length
HMACs; first-RP binding; missing permissions and wrong RP scopes; replacement
grants; PIN change; reset; UP/UV consumption; success resetting PIN retries;
and the eight-attempt limit across authenticator runtime recreation.
Recreating runtime in a virtual test is not a physical power-cut test.

## Threat model: restoring old encrypted PIN state

This limitation was already part of the hardening review. The 2026-09-06
follow-up adds a host reproduction and an explicit closure decision gate.
No storage format or device configuration changes implement replay protection.

The vendored `state.rs` persists `consecutive_pin_mismatches` and `pin_hash`
in `persistent-state.cbor`. `decrement_retries` saves a debit before PIN
verification, and a successful PIN resets the persistent debit. Reloading
valid state accepts the stored counter without comparing it with any trusted
external generation. The per-power-cycle counter lives in runtime state.

Assume an attacker can capture and later restore a complete valid encrypted
filesystem snapshot at the same flash addresses on the same device, under its
unchanged flash key. The old record can restore unused PIN attempts. Rebooting
also resets the volatile limit. The attacker does not need to know the flash
key to replay captured ciphertext. A partial or inconsistent copy may fail;
the threat assumes a coherent old copy. This can also restore old credential,
signature-counter and PIN-policy state. If the PIN has changed since capture,
restoring the complete old state may restore the old PIN verifier too.

`restoring_old_valid_state_restores_pin_attempts_on_the_host` exercises both
PIN protocols through the actual CTAP dispatcher. It saves a synthetic valid
state in RAM, exhausts eight attempts across runtime recreation, confirms that
the correct synthetic PIN remains blocked, restores the saved bytes, then
observes eight attempts and an accepted new attempt. No counter bytes are
edited. All 26 tests in `tools/test-persistent-state` passed on 2026-09-06.
This demonstrates the application-state behavior. It does not emulate AES-XTS,
restore a physical board, or establish how accessible its flash is.

Firmware `SECURE_VERSION` compares an application's signed epoch with an eFuse
floor. It does not compare the age of mutable FIDO state. The current firmware
can accept old state without any firmware downgrade. AES-XTS confidentiality,
filesystem checksums, a file MAC, a hash chain and an authenticated journal
stored entirely in the same flash cannot distinguish a complete old valid
snapshot from the newest one.

### What ROM closure changes

Full ROM download closure is intended to remove the ROM command path for
reading and writing flash over applicable USB and UART transports. Secure
download mode is different: it retains basic flash writes and is not an
equivalent closure policy. Verify both transports on the exact board and keep
normal USB-FIDO enabled. See Espressif's
[download-mode description](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s2/security/security.html#uart-download-mode).

With ROM closed and JTAG disabled, a physical attacker loses convenient
software access paths. The signed USB updater must remain confined to its
application slots, with no arbitrary FIDO-state restore command. However,
physical access to flash signals or silicon, fault injection, vulnerable
authorized firmware, and compromise of retained recovery material remain
separate risks. Physical access depends on the board and flash packaging;
Espressif lists variants with [in-package flash](https://documentation.espressif.com/esp32-s2_datasheet_en.html).
A simple external flash-chip replacement is not a demonstrated attack on this
board. Package access difficulty does not establish freshness or measured
physical resistance.
An older trusted bootloader replay is also a separate boot-chain concern.

| Option | Benefit | Limit or cost |
| --- | --- | --- |
| Close ROM and keep debug disabled | Reduces accessible software restore paths | Does not give mutable state a trusted freshness reference |
| Authenticate/journal the state in flash | Detects unauthorized edits and helps atomic recovery | A complete old valid snapshot still replays; format and crash semantics need a separate design |
| Bind state to a protected monotonic counter | Can detect rollback when updates and recovery are atomic | Needs a suitable counter outside replayable flash, endurance analysis and power-loss handling |
| Secure element or secure MCU with enforced PIN retries | Can keep retry state and key-use policy within a protected boundary | A chip that merely signs host requests is insufficient; requires hardware and provisioning design |

### Recommendation for this ESP32-S2

The current implementation has no reliable protection against complete valid
FIDO-state replay by an attacker who can replace the stored ciphertext.
Keep the tested Secure Boot, flash encryption, restricted updates, fail-closed
loader, PIN limits and fresh presence checks. Qualifying ROM closure reduces
access, but must not be reported as fixing this limitation.

Do not use firmware eFuses as a per-attempt counter. The S2
[security-version field has only 16 bits](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s2/api-reference/system/ota.html#anti-rollback).
Other eFuse space is finite and has field-specific permissions and coding
constraints; RS-coded blocks cannot be repeatedly extended as a normal log.
See the [eFuse manager](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s2/api-reference/system/efuse.html).
Do not consume spare fields or the shared ROM/security-version write lock for
this purpose. A static eFuse-backed MAC secret authenticates old records too.
RTC RAM loses its role as a reference after full power loss. Ordinary external
EEPROM, flash or FRAM improves endurance, not replay resistance. An online
trusted counter would change the offline authenticator model and availability.

If resistance to captured-device retry restoration is required, defer that
security claim and use a later hardware design with protected mutable state.
A protected counter can detect replay under a trusted MCU policy, but an
attacker must not be able to substitute an old counter response or bypass its
use. A secure element or secure MCU that enforces PIN attempts and authorizes
non-exportable credential-key use gives a stronger boundary against MCU
compromise. Merely adding a signing chip or an unauthenticated counter does
not meet that requirement. No component is selected here.

### Counter endurance, power loss and recovery requirements

A future counter design needs a reviewed transaction protocol, not just a
counter read added to startup:

- Commit an irreversible attempt debit before testing a guess or releasing
  its result. Bind the persistent generation, PIN policy and success/reset
  state to the trusted reference. A success must not allow an old success
  record to replenish retries after later failures.
- After a power cut between debit, flash commit and response, fail closed or
  conservatively charge the attempt. Test every boundary, duplicate requests,
  replayed journal slots and uncertain counter responses. Never decrement the
  trusted reference or initialize eight retries to resolve a mismatch.
- Budget successful PIN checks, failed checks, recovery writes, malicious
  request volume and power interruptions. For scale, 100 counter updates per
  day for ten years is 365,000 updates. Validate the selected part's counter
  range, endurance and temperature-dependent retention separately from flash
  wear levelling. Define exhaustion as a service/recovery event, not wraparound.
- Require authenticated counter responses and device binding, serialize
  updates, and define behavior when the counter is missing or faulty. A host
  must not be able to replace the peripheral with one reporting an old value.
- Old backups must not reset the counter. Define an authenticated recovery or
  migration procedure that preserves the attempt policy or retires the old
  credential state. Restoring on another device is not assumed possible.

As an example of why component details matter, Microchip documents a
[counter](https://onlinedocs.microchip.com/oxy/GUID-E8090678-FB6F-4FDB-B2FD-C019408533ED-en-US-2/GUID-EABA157C-F433-421D-ADC3-EC4B495E96FB.html)
with a finite maximum of 2,097,151. A power interruption can consume more than
one count; the cited TFLXTLS configuration does not attach counters to keys.
These properties alone do not implement FIDO PIN policy or qualify that part
for this project.

### Long random PIN as additional protection

A long uniformly random PIN increases guessing cost even when an attacker
can restore retries. For comparison, six random decimal digits provide about
20 bits, twenty random decimal digits about 66 bits, and twenty characters
chosen independently from 62 letters/digits about 119 bits. These are search
space calculations, not attack-time measurements. A memorable human pattern
does not inherit these figures merely by having the same length.

For this prototype, prefer a long independently generated PIN when supported
by the actual client entry flows, and keep independent account recovery.
The reviewed verifier stores a truncated 16-byte SHA-256 PIN hash without a
password-hardening KDF. If plaintext state becomes available, guesses need not
obey the device's retry timer. A strong PIN still does not protect credential
keys extracted directly, a compromised PIN-entry host, or an older backup
containing a weaker PIN verifier. This analysis does not establish the strength of any configured PIN.

Keep original private backups and record capture generation, recovery scope
and replay implications privately. Do not delete originals as a workaround.

## Device acceptance before irreversible hardening

Before final ROM closure, explicitly record whether the device operator accepts the
remaining physical-state replay risk for this prototype. If reliable
captured-device retry protection is required, this gate remains open pending
a suitable hardware/state design. Do not count firmware-floor rejection,
ordinary PIN exhaustion, a MAC check or ROM denial as proof of state freshness.
This review adds no authority for a physical snapshot restore or PIN change.

Qualify newly built normal and fallback images, with the selected physical
input, before preparing a new counter plan. Re-run PIN-authenticated use of
existing credentials, token expiry, replacement grants, fresh physical
presence and cancellation, signed updates, invalid/old image rejection, A/B
failure recovery and the agreed power-cut cases. Tests that change a PIN,
exhaust attempts, or reset storage require separately scoped device authority;
software coverage does not authorize them on an account key.

The corrected images need a security epoch that excludes the older vulnerable
images. Reassess the installed bootloader, A/B compatibility and available bits
before selecting it. The previous epoch-4 counter plan is superseded and must
not be executed. No new counter value or ROM restriction is authorized here.
