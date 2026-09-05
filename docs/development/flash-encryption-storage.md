# Release flash-encryption storage path

RissoKey has a separate ESP32-S2 storage backend for release-mode flash
encryption. On 2026-09-05 the authorized protected prototype passed encrypted
pattern readback, littlefs format, mount and both initialization-marker checks.
Normal FIDO operation remains blocked by missing original attestation material.
The storage correction and runtime installation made no eFuse changes.

## Build contract

The backend requires all of the following:

- Cargo `--release`;
- the `release-flash-encryption` feature;
- its implied `non-strapping-user-presence` feature;
- the `signed-ab-encrypted` partition profile;
- ESP32-S2; and
- active flash encryption at runtime.

`build.rs` rejects a feature/profile mismatch and rejects a debug build. The
runtime checks `esp_hal::efuse::flash_encryption()` before mounting
`fido_store`. It stops instead of falling back to raw reads or formatting the
partition when encryption is disabled.

Build the host-only ELF with assigned USB identity values in the environment:

```sh
RISSO_KEY_MCU=esp32s2 \
RISSO_KEY_PARTITION_PROFILE=signed-ab-encrypted \
RISSO_KEY_USB_VID="$RISSO_KEY_ASSIGNED_USB_VID" \
RISSO_KEY_USB_PID="$RISSO_KEY_ASSIGNED_USB_PID" \
RISSO_KEY_USB_SERIAL="$RISSO_KEY_DEVICE_SERIAL" \
RISSO_KEY_UPDATE_KEY_DIGEST_HEX="$RISSO_KEY_TRUSTED_PUBLIC_KEY_DIGEST" \
./tools/cargo-esp build --locked --release --bin rissokey \
  --no-default-features \
  --features mcu-esp32s2,ctaphid-bringup,fido-stack,signed-ab-update,usb-signed-update,release-flash-encryption
```

The command builds an ELF. It does not create permission to flash it or alter
eFuses.

## Partition and transport rules

`partitions-ab-encrypted.csv` keeps the signed A/B geometry unchanged and marks
`otadata`, both application slots, and `fido_store` as encrypted. The normal
development layouts remain unchanged.

Raw ESP ROM SPI reads return ciphertext when flash encryption is active. The
release backend therefore maps only the required encrypted regions through the
ESP32-S2 DROM cache:

| Purpose | Physical flash | DROM window |
| --- | ---: | ---: |
| `otadata` reads | `0x000000..0x020000` | `0x3f390000..0x3f3b0000` |
| `ota_0` descriptor | `0x020000..0x030000` | `0x3f3b0000..0x3f3c0000` |
| `ota_1` descriptor | `0x200000..0x210000` | `0x3f3c0000..0x3f3d0000` |
| `fido_store` | `0x3e0000..0x400000` | `0x3f3d0000..0x3f3f0000` |

The linker asserts that application read-only data ends at or before
`0x3f390000`. The final DROM page at `0x3f3f0000` stays available to the
ESP-IDF-compatible boot path.

Encrypted writes use the ESP32-S2 ROM encryption function in 32-byte blocks.
The backend copies each block into a four-byte-aligned RAM buffer because the
ROM function may modify its source. It clears the buffer after the call.
The mapping call, each low-level erase or encrypted-write call, and cache
invalidation execute from RAM while the flash operation holds a critical
section. Credential-store reads copy plaintext only from fixed cache mappings.
USB OTA readback temporarily remaps one descriptor window, copies at most one
page, and restores the fixed mapping before returning. Range checks confine
littlefs and both OTA slots to their own partitions.

The development backend keeps its existing four-byte raw-flash program size.
The encrypted backend uses a 32-byte program size. An existing unencrypted
littlefs image is not an in-place migration target. A protected-device flow
must create a fresh encrypted store through an explicit provisioning step. A
mount or integrity failure must never trigger an automatic format.

The protected one-shot storage provisioner also selects this backend and the
external active-low GPIO16 confirmation input. The development provisioner
retains GPIO0. Both require the explicit `storage-provisioning` build feature;
normal authenticator firmware cannot format the store.

`provision-storage` does not install the FIDO attestation key or certificate.
Before a fresh-store erase, verify a recoverable copy of the original identity.
After initialization, restore that same identity before expecting the normal
runtime to enter USB polling. See [attestation recovery](../guides/attestation-recovery.md).

## Evidence and remaining physical gate

On 2026-09-04 the exact release feature set above compiled for
`xtensa-esp32s2-none-elf`. The ELF placed all new low-level flash functions in
`.rwtext`. `_rodata_end` was `0x3f001c1c`, below the reserved DROM start at
`0x3f390000`. The generated application image was 400,512 bytes, below either
1,966,080-byte A/B application slot. Pure host tests covered mapping bounds and
write alignment. The persistent-storage fault harness also passed its eight
existing tests.

A later clean preflight rebuilt the protected bootloader, secure-version 3
normal runtime, same-secure-version rollback-failure fixture, and one-shot
storage provisioner from source commit `fe17f88` and pinned ESP-IDF commit
`fff9895c`. All 15 package file hashes, executable signatures, and ciphertext
round trips at their final flash offsets passed. The failure fixture is absent
from every initial-install and recovery set.
The same preflight accepted a read-only summary from the disposable target
against the pristine eFuse profile, then returned it to normal FIDO operation.
It wrote neither flash nor eFuses. The redacted record is
[`docs/evidence/protected-preflight-esp32s2-fe17f88.json`](../evidence/protected-preflight-esp32s2-fe17f88.json).

On 2026-09-05 hardware diagnosis found two mapping defects. ESP32-S2 DROM
uses IBUS2, so it requires `Cache_Ibus_MMU_Set`. Its first argument must also
include `SOC_MMU_ACCESS_FLASH`, bit 15. Commit `ef2001b` corrects both through
a RAM helper that disables and restores ICache while interrupts are masked.
Eight public pattern blocks then passed decrypted readback on the device,
followed by successful format, mount and initialization markers. Raw flash
readback matched the independent Keychain encryption reference for the probe.

The signed and encrypted normal runtime was installed at `0x20000`; all
413,696 written bytes matched physical readback. The operation preserved
`fido_store` and `otadata`. No FIDO USB device appeared after reset or a USB
power cycle. Source inspection identifies a missing mandatory attestation
identity as a boot blocker; no device trace establishes the exact halt site.
That missing development identity was subsequently replaced with explicit
owner authorization for the second test device. Protected identity import,
expected packed attestation signature, credential creation and assertion,
and assertion after USB power cycling passed. After explicit fresh OTA metadata
initialization, signed USB update and automatic rollback also passed with the
same credential intact. The authorized encrypted ROM recovery then passed
complete physical readback and final FIDO/credential checks while preserving
boot metadata, credential storage and all eFuses. The
redacted historical record is
[encrypted DROM diagnosis](../evidence/encrypted-drom-diagnosis-20260905.json).
The follow-up is [protected attestation import](../evidence/attestation-import-esp32s2-20260905.json).
The update and rollback results are in
[protected OTA acceptance](../evidence/protected-ota-esp32s2-20260905.json).
