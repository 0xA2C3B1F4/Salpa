# ESP32-S2 hardening before final ROM closure

Status on 2026-09-05: design and source review only. The existing protected S2
is an enrolled account key. This document does not authorize flashing, eFuse
writes, key replacement or key deletion. The reusable eFuse plan remains
unapproved, and its final ROM stage now has no burn operations.

## Verified starting point

[Protected acceptance](../evidence/protected-ota-esp32s2-20260905.json) records
Secure Boot V2, release-mode flash encryption, signed USB installation,
failed-candidate rollback, encrypted ROM recovery and preserved credentials.
The normal runtime is from `ef2001b`, with security version 3. Full ROM download
remains available. This review reads source and recorded evidence; it does not
reset the enrolled device or establish a fresh physical identity/revision.
Reconfirm both immediately before any later device-specific operation.

The installed-package bootloader configuration has
`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` disabled. RissoKey's USB update code rejects
an image security version below the running application's value. Its custom
OTA confirmation marks boot metadata valid but does not advance an eFuse
counter. These are useful update checks, without hardware-enforced minimum
firmware age.

## ROM policy and shared eFuses

The source basis is ESP-IDF 6.1 commit
`fff9895c82d744c7237be8847347bdd1b07c6643`, matching the protected build.
The [S2 eFuse table](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/efuse/esp32s2/esp_efuse_table.csv)
and [S2 implementation](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/efuse/esp32s2/esp_efuse_fields.c)
distinguish these settings:

| Field | Meaning in the pinned S2 implementation | Design consequence |
| --- | --- | --- |
| `ENABLE_SECURITY_DOWNLOAD` | Restricted ROM maintenance | Does not completely close ROM download |
| `DIS_DOWNLOAD_MODE` | Disables all download boot modes; this is what `esp_efuse_disable_rom_download_mode()` sets | Candidate for final closure, subject to exact revision review and testing |
| `DIS_USB_DOWNLOAD_MODE` | Disables USB OTG use in UART download boot mode | A transport-specific restriction, not a substitute for all-mode closure |
| `DIS_USB` | Disables the USB peripheral | Incompatible with the intended normal USB FIDO/update service; keep unset |
| `DIS_FORCE_DOWNLOAD` | Disables the forced-download function | Already zero and write-protected in the established baseline; it cannot now be changed independently |
| `SECURE_VERSION` | 16-bit monotonic firmware security field | A finite security-epoch budget, not a version number to increment on every release |

`DIS_DOWNLOAD_MODE`, `DIS_USB_DOWNLOAD_MODE`, `ENABLE_SECURITY_DOWNLOAD`,
`DIS_LEGACY_SPI_BOOT` and `SECURE_VERSION` share `WR_DIS` bit 18. Protecting any
one through that group also freezes the security-version counter. Do not
write-protect this group while future security-floor increases are required.
Disabling download is itself a one-way 0-to-1 change; group protection is a
separate operation. The earlier shared group at bit 2 already locks JTAG,
cache controls, `DIS_USB` and `DIS_FORCE_DOWNLOAD` in the current baseline.

The previous plan's final step only enabled restricted download. It has been
replaced with a blocked design gate so that its name cannot imply complete
closure. Espressif also distinguishes restricted download from full closure in
its [S2 flash-encryption guide](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s2/security/flash-encryption.html#best-practices).
An earlier successful USB-ROM recovery does not establish that transport's
availability in restricted download mode. Test the intended UART/USB route
on a separate board before choosing restricted maintenance as an interim step.

The existing protected bootloader selects secure download in its defaults.
[Secure Boot initialization](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/bootloader_support/src/esp32s2/secure_boot_secure_features.c)
can burn security settings, and the IDF flash-encryption initialization also
changes download policy. The current no_std application does not run IDF's
normal application startup. Review actual call paths and linked configuration;
do not infer first-boot safety from a menu setting. This source release keeps
the accepted bootloader configuration unchanged.

## Required order for the current S2

1. Preserve the exact signing root, flash key, attestation pair and credential
   store. Verify an independently usable account recovery method. Read and bind
   the board revision and all current eFuse permissions to private evidence.
2. Build and test the final bootloader and application policy on a separate,
   explicitly authorized board. Review normal and fallback boot paths,
   provisioning binaries, test features, alternative boot paths and debug
   settings. Retain release-feature checks and fresh GPIO16 presence.
3. Implement hardware anti-downgrade only with a complete confirmation policy.
   Both fallback and candidate must satisfy the proposed floor. Test an older
   correctly signed image, a wrong-key image, failed self-test, torn metadata,
   power loss around confirmation, and exhaustion of the 16-bit field.
   The current custom Rust confirmation does not call the IDF OTA API that
   normally manages the security epoch. A bootloader toggle alone is insufficient.
4. Test signed USB updates and reset recovery with both valid OTA slots under
   the final policy. Confirm the same credentials before and after each test.
   Today's inactive slot contains a deliberately failed candidate in the last
   acceptance record; do not assume there are already two valid recovery images.
5. Complete offline backup transfer and restore checks. Select full ROM closure
   only after accepting that loss of both bootable applications, a damaged
   bootloader, or some interrupted writes may be permanently unrecoverable.
6. Prepare a device-specific change sheet with current values, proposed field
   changes, exact order, shared protection effects and passed physical evidence.
   Full closure would set `DIS_DOWNLOAD_MODE`, while leaving `DIS_USB` unset
   and preserving future `SECURE_VERSION` writes. Additional fields and their
   locks require their own justification. Request immediate owner approval
   for that concrete sequence, then verify normal boot, USB update and absence
   of ROM access on both applicable transports.

The pinned [IDF OTA description](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/docs/en/api-reference/system/ota.rst)
describes anti-rollback and its finite counter. The minimum security epoch
must advance only after a qualified candidate is accepted and a compatible
fallback exists. A/B recovery and rejection of old vulnerable firmware are
separate requirements. There is no final burn sequence ready for approval yet.

## Persistent state and physical attacks

AES-XTS protects flash confidentiality, and littlefs handles consistency under
interrupted writes. Neither proves that a presented encrypted snapshot is the
newest one. Review rollback of PIN retries, signature counters and credential
state separately. Closing ROM download removes one access path, while an
attacker with physical access to flash may still attempt snapshot replacement.
The resulting attack has not been demonstrated against this enrolled device.

Host-side fault models can test atomic state changes and fail-closed behavior.
A MAC can detect unauthorized modifications but cannot by itself detect replay
of an old valid state. Strong rollback resistance needs a trusted monotonic
reference outside the replayable storage. Reusing the finite firmware eFuse
field for PIN attempts or every signature would exhaust it and is unsuitable.
Physical fault injection, side channels and invasive extraction remain
unevaluated; documentation must not claim resistance based on software tests.

## Key custody and a later hardware revision

Keychain authentication controls the helper's use of its records. Retained
plaintext originals remain another access path. The encrypted backups are
currently staged on connected storage, with offline transfer deferred by the
owner. Follow [key management](../guides/key-management.md): copy to separate offline
media, restore and compare there, record the result privately, and only then
seek the separate retention/deletion decision. Keep passwords elsewhere.
Deleting an APFS/SSD file does not prove older snapshots or copies are erased.
Flash-key retention depends on the selected recovery model; attestation
recovery material remains a durable private asset.

For the current S2, prioritize tested boot policy, controlled updates, PIN and
presence handling, fail-closed storage, and recoverable maintainer custody.
For a later board, evaluate a secure element or secure MCU with non-exportable
credential keys, authorized operations, protected retry/counter state and a
reviewed provisioning/recovery design. A chip that blindly signs commands
from a compromised host MCU would leave significant gaps. No component has
been selected, and no physical security or certification level is claimed.
