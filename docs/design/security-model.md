# Security model

## Protected assets

Salpa protects credential private keys, resident credential metadata, PIN
state, attestation private keys, and the integrity of user-presence decisions.
Account identifiers and USB serial numbers are private operational data even
when they are not cryptographic secrets.

## Trust boundaries

SoloKeys and Trussed own CTAP2 semantics, credential formats, PIN protocols,
CBOR and COSE handling, and cryptographic operations. Salpa owns USB HID and
CTAPHID transport, ESP platform integration, randomness, storage, physical
user presence, device identity, provisioning, and build configuration.

The host, browser, USB bus, and USB power source are untrusted. Development
hardware with readable flash or enabled debug access is also untrusted against
an attacker with physical possession.

## Required properties

- Every protected operation requires a fresh physical confirmation.
- A previous button press cannot approve a later request.
- Cancellation stops a pending user-presence wait.
- RNG health failure stops credential operations.
- Mount, read, integrity, or version failure never formats credential storage.
- Normal firmware cannot format persistent credential storage.
- Missing, unreadable, or malformed `persistent-state.cbor` fails closed at the
  CTAP boundary. Normal firmware never replaces it with default PIN, retry,
  `alwaysUv`, counter, or key-reference state.
- Only an explicit provisioning image may authorize first state creation by
  writing a one-time marker. The authenticator saves valid initial state before
  it removes that marker.
- The firmware rejects missing or invalid project attestation instead of using
  an upstream fallback identity.
- The mounted attestation key must contain a valid nonzero P-256 scalar below
  the group order.
- PINs, keys, credential IDs, account identifiers, and raw sensitive packets
  never enter normal logs or Git history.
- Release firmware exposes only the FIDO USB interface.
- CTAPHID request and response buffers, temporary RNG health samples, parsed
  attestation key material, and the Trussed initialization seed are zeroized
  when their operation ends.

## Hardware profiles and achieved protection

The earlier development S2 profile uses unencrypted flash and GPIO0/BOOT for
presence, with debug and download access available. It is for bring-up.

The protected S2 configuration accepted on 2026-09-05 uses eFuse-enforced Secure
Boot V2, release-mode AES-XTS flash encryption, disabled JTAG, and an active-low
GPIO16 presence button. Encrypted credential storage, signed USB update,
confirmation, rollback, and encrypted ROM recovery have passed on that device.
See the [testing guide](../testing/README.md). These statements describe the
accepted device, not every build with an ESP32 chip or a similarly named feature.

On 2026-09-06, the separately qualified hardening stage advanced the application
security floor to 5 and set `DIS_DOWNLOAD_MODE`. The physical USB ROM-entry
attempt no longer exposed the downloader. Normal FIDO, PIN authentication,
signed updates and failed-candidate fallback passed afterward. UART denial
was not electrically tested. See the [final hardening results](../testing/esp32s2-final-hardening.md).

The MCU holds flash-encryption key material in protected eFuses. Credential
keys and FIDO state are used by software through Trussed and the decrypted
storage path. The RSA firmware signing key belongs to the maintainer and is
separate from both the device flash key and the FIDO attestation key. The
[macOS Keychain workflow](../guides/key-management.md) protects maintainer operations;
it is not on-device credential isolation.

## Remaining threat boundaries

- Flash encryption protects stored confidentiality. It does not isolate keys
  in use from compromised authorized firmware, authenticate all mutable state,
  or prove freshness against replay of an earlier encrypted storage snapshot.
- Secure Boot checks the normal boot chain. The final tested device closes ROM
  download, removing ordinary ROM read/write recovery. This does not establish
  resistance to physical flash access, side channels or fault injection.
- Signed updates verify the trusted key, image and version. A/B rollback returns
  to a working image. The tested epoch floor separately rejects older
  applications; it does not prove FIDO-state freshness or prevent replay of
  every older bootloader signed by the retained root.
- PIN handling relies on the host to present the PIN entry and on the MCU/FIDO
  stack for enforcement. A fresh button press proves physical presence, but
  the board has no trusted display showing the relying party or requested act.
- CRCs and littlefs recovery provide consistency checks, not a proof of security
  against deliberate physical state modification or counter rollback.
- Restoring an old valid FIDO-state snapshot on the same device can restore
  PIN attempts even under current firmware. This behavior is confirmed in the
  isolated host test, not by restoring the physical device. ROM closure removes
  an access path; reliable state freshness requires a protected reference
  outside replayable storage. A long random PIN raises guessing cost but does
  not fix replay or protect directly extracted credential keys.
- No independent fault-injection, side-channel, or invasive-attack assessment
  establishes resistance to a captured-device attacker. Controlled storage
  interruption tests do not cover every electrical brownout condition.

The [physical-attack applicability review](physical-attack-applicability.md)
compares the S2 package and board reference with AR2022-003, AR2023-007 and
Courdesses's research. It distinguishes potential S2 applicability from results
on ESP32/C3/C6. In-package flash must not be described as an inaccessible bus,
and ROM download closure does not remove normal boot-time decryption.

A secure element or secure MCU may strengthen key isolation and physical
protection. Its policy enforcement, connection to the host MCU, provisioning,
and recovery must be designed and evaluated as part of the complete system.
Salpa has not completed FIDO certification or an independent security review.
Do not use Salpa as the only account login or recovery method. Set up an
independent alternative and test it with Salpa unplugged. Device lockout or
failure may require registering a replacement security key with each service.

Espressif describes [boot authentication, flash confidentiality and debug/download restrictions](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s2/security/security.html).
FIDO's [security levels](https://fidoalliance.org/security-certification-authenticator-security-levels/)
distinguish protocol assurance from execution isolation and physical resistance.
Neither reference certifies this implementation.

## Out of scope for version 0.1

Wi-Fi, BLE, NFC, CCID, PIV, OpenPGP, OATH, cloud recovery, custom cryptography,
and production manufacturing provisioning remain out of scope.

The [PIN/UV source correction and replay threat model](../development/pin-token-security.md)
distinguish token expiry and constant-time comparisons from unproven physical
attack resistance. The final hardening report records PIN and GPIO16 checks
for its accepted image. Later firmware changes require new device acceptance
appropriate to their scope; they do not inherit that result automatically.

The [USB update lifetime policy](../guides/usb-signed-update.md) bounds an
approved transfer with device-owned idle and absolute deadlines. This limits
stale approval; it does not change the image-signature trust boundary or prove
freshness of mutable FIDO state. The
[current acceptance status](../testing/esp32s2-results.md#current-acceptance-status)
records the normal-image deadline tests and remaining update qualification.

The [ESP32-S2 memory-protection policy](esp32s2-memory-protection.md) configures
and locks CPU RAM permissions before FIDO starts. It complements the stack
watchpoint. The [current acceptance status](../testing/esp32s2-results.md#current-acceptance-status)
separates normal-image operation and permission readback from prohibited-access
tests on an instrumented image and static checks of the normal fault handler.
Neither control isolates credential secrets from all authorized firmware.
