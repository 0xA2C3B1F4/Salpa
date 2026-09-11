# Release flash-encryption storage path

Salpa has a separate ESP32-S2 storage backend for release-mode flash
encryption. Protected prototype tests passed encrypted pattern readback,
littlefs format and mount, initialization-marker checks, and normal FIDO
operation. The [S2 test results](../testing/esp32s2-results.md) distinguish
storage initialization from identity import and credential acceptance.

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
SALPA_MCU=esp32s2 \
SALPA_PARTITION_PROFILE=signed-ab-encrypted \
SALPA_USB_VID="$SALPA_ASSIGNED_USB_VID" \
SALPA_USB_PID="$SALPA_ASSIGNED_USB_PID" \
SALPA_USB_SERIAL="$SALPA_DEVICE_SERIAL" \
SALPA_UPDATE_KEY_DIGEST_HEX="$SALPA_TRUSTED_PUBLIC_KEY_DIGEST" \
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

## Validation and DROM correction

Target-build validation must check that low-level flash functions reside in
`.rwtext`, that application read-only data stays below the reserved DROM window,
and that the application fits its A/B slot. Host tests cover mapping bounds and write
alignment. These checks cannot prove encrypted flash behavior on hardware.

Hardware diagnosis identified two mapping defects. ESP32-S2 DROM uses IBUS2,
so it requires `Cache_Ibus_MMU_Set`. Its first argument must also include
`SOC_MMU_ACCESS_FLASH`, bit 15. The correction uses a RAM helper that disables
and restores ICache while interrupts are masked. Eight public pattern blocks
then passed decrypted readback, followed by successful format, mount and
initialization-marker checks. Raw flash readback matched an independent
AES-XTS encryption reference for the probe.

The [S2 test results](../testing/esp32s2-results.md) summarize the protected
storage, identity import, credential persistence, signed USB update, rollback
and encrypted ROM recovery tests. Storage initialization alone does not prove
that an attestation identity is installed or that FIDO works. Repeat those
checks for each provisioned device and its own recovery material.
