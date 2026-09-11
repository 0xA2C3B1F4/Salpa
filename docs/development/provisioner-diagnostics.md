# Provisioner RTC diagnostics

The standalone `provision-storage` image records a non-secret four-word progress
record in persistent RTC slow memory. It does not add a diagnostic interface to
the normal authenticator or bypass the fresh five-second presence gesture.

Locate `RISSO_PROVISION_DIAGNOSTIC` in the exact provisioner ELF symbol table.
Read its four 32-bit words only when the record survives the reset used to
reach ROM download. The physical BOOT plus RESET test on this board returned
no valid record despite USB remaining attached. Do not rely on RTC retention
through EN/RESET or loss of power, and never interpret an invalid record.

The record is `[0x52504431, stage, detail, 0x52504431 ^ stage ^ detail]`.
Both magic and checksum must match before interpreting it. This record proves
the observed execution stage only, not credential persistence or recovery.

| Stage | Meaning |
| --- | --- |
| 1 | Application entered |
| 2 | GPIO initialized |
| 3 | Waiting for physical gesture |
| 4 | Fresh hold accepted |
| 5 | About to initialize flash encryption |
| 6 | Encrypted mappings initialized |
| 7 | About to format littlefs |
| 8 | Format returned successfully |
| 9 | Fresh filesystem mounted |
| 10 | Storage-version marker written and verified |
| 11 | Persistent-state initialization marker written and verified |
| 12 | Initialization verified; two-pulse success loop entered |
| 100 | Physical-presence window expired |
| 101–107 | Encryption initialization error: disabled, mapping, range, alignment, unlock, erase, or write. Detail holds the driver return code where applicable. |
| 110–113 | Format, mount, version marker, or initialization marker failed |

On ESP32-S2, the current esp-println UART implementation writes to UART0, even
when the bootloader's console is USB CDC. No USB console output from the
provisioner is therefore expected. An illuminated LED alone is not a success
gate: it can remain high after the presence gesture when a subsequent step fails.

## Visible result

The provisioner no longer prints blocking UART notices in its control path.
After the fresh hold, it repeats a pulse group with a two-second dark interval:

| Pulses | Meaning |
| --- | --- |
| 1 | Presence window expired; no format attempted |
| 2 | Format, mount and both initialization markers verified |
| 3 | Encryption mapping or storage backend initialization failed |
| 4 | Format failed |
| 5 | Mount failed |
| 6 | Storage-version marker failed |
| 7 | Persistent-state initialization marker failed |

A steady LED or an absent pulse group is not success. Readback, normal-runtime
mount, credential persistence and recovery remain separate physical gates.
Stage 114 records a storage backend initialization failure.

Two pulses prove storage initialization only. This image does not install
`/fido/sec/00` or `/fido/x5c/00`. The normal runtime requires the original
attestation key and certificate at those paths before USB polling starts.
Verify an original backup before any erase and restore that identity afterwards;
see [attestation recovery](../guides/attestation-recovery.md).

## ESP32-S2 DROM correction

The encrypted storage and OTA mappings use `Cache_Ibus_MMU_Set`, because the
ESP32-S2 DROM window is served by IBUS2. The MMU update runs with interrupts
masked and ICache disabled. Its RAM helper takes scalar addresses and restores
ICache on both success and failure before any mapped data is accessed.

Source references are pinned ESP-IDF commit
`fff9895c82d744c7237be8847347bdd1b07c6643`:
`components/hal/esp32s2/include/hal/mmu_ll.h`,
`components/hal/esp32s2/include/hal/cache_ll.h`, and
`components/esp_rom/esp32s2/include/esp32s2/rom/cache.h`.
The ROM MMU API forbids ordinary MMU updates during cache suspension, so this
sequence uses disable/enable instead of suspend/resume.

The [ESP32-S2 datasheet](https://documentation.espressif.com/esp32-s2_datasheet_en.html)
defines CHIP_PU low as chip power-off. An attached USB cable is therefore not
sufficient evidence for RTC retention when the board's EN/RESET is pressed.

## Encrypted roundtrip probe

After fresh approval, the standalone provisioner erases the last fido_store
sector at `0x3ff000`, writes eight distinct public 32-byte pattern blocks, and
compares all written bytes through the decrypted mapping after each write.
On success it erases that sector again and proceeds to littlefs format. This
probe is absent from normal firmware and cannot run without the provisioning
gesture. It does not change keys, boot metadata, or eFuses.

Additional repeating LED pulse counts are 8 for probe erase failure, 9 for
write failure, 10 for decrypted readback mismatch, and 11 for read failure.
RTC stages 120–126 record probe progress without storing the data. Stage 110
now records the littlefs error code in its detail word. A two-pulse final
result still requires successful format, mount, and both marker checks.

A decrypted readback mismatch despite successful ROM writes exposed a mapping
requirement in the pinned IDF `components/soc/esp32s2/include/soc/ext_mem_defs.h`
and `hal/mmu_ll.h`: ESP32-S2 flash entries require `SOC_MMU_ACCESS_FLASH`, bit 15.
`Cache_Ibus_MMU_Set` directly ORs its first argument into each physical page;
it does not add this flag. The shared helper passes `1 << 15` instead of zero
for every fixed and temporary mapping. With that correction, the pattern probe
and storage initialization passed, and eFuse readback remained unchanged.

See the [S2 test results](../testing/esp32s2-results.md) for the protected
storage and subsequent FIDO checks. The two-pulse result remains a storage-only
signal; it does not prove identity installation or credential readiness.
