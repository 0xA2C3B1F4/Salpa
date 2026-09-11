# Reversible 0xE000 partition migration

The Secure Boot V2 bootloader does not fit before the legacy partition table at
`0x8000`. This gate moves the table to `0xE000` on a disposable ESP32-S2 while
keeping Secure Boot, flash encryption, and every irreversible eFuse setting
disabled.

This is a migration test, not a protected release configuration. A host build,
package, successful flash command, or boot message proves only its own gate.
USB, CTAPHID, credentials, persistence, and rollback require separate physical
evidence.

## Layout and rollback boundary

The table cannot simply move from `0x8000` to `0xE000`: that sector belongs to
the legacy NVS partition. The migration layout therefore keeps the application
at `0x10000`, moves NVS and PHY data behind the shortened application, and
preserves the credential store exactly:

| Region | Legacy layout | Migration layout |
| --- | --- | --- |
| Partition table | `0x8000` | `0xE000` |
| NVS | `0x9000` + `0x6000` | `0x3D0000` + `0x6000` |
| PHY init | `0xF000` + `0x1000` | `0x3D6000` + `0x1000` |
| Factory app | `0x10000` + `0x3D0000` | `0x10000` + `0x3C0000` |
| `fido_store` | `0x3E0000` + `0x20000` | unchanged |

Moving NVS/PHY overwrites the final 64 KiB of the legacy application. Moving
the table overwrites one legacy NVS sector. Byte-identical rollback consequently
needs the complete 4 MiB pre-migration flash image. An explicitly unused,
disposable device may instead use the package's functional legacy restore. That
restore reinstalls a known legacy bootloader, table, and application, erases
legacy NVS/PHY, and preserves `fido_store`; it does not reproduce prior NVS data.

`scripts/check_partition_layouts.py` validates both layouts, all region bounds,
and the exact `fido_store` invariant. Application builds select the migration
contract only with `SALPA_PARTITION_PROFILE=e000-migration`; the normal
default remains `legacy-0x8000`.

## Host-only package

Use a clean source commit and new external build directories. The custom
bootloader builder accepts only ESP-IDF v6.1 commit
`fff9895c82d744c7237be8847347bdd1b07c6643` and rejects every Secure Boot or
flash-encryption option:

```sh
python3 tools/build-e000-migration-bootloader.py \
  --idf-path "$IDF_PATH" \
  --build-dir "$SALPA_BOOTLOADER_BUILD"
```

Build the Rust application with a non-production test identity supplied only
through the environment:

```sh
SALPA_USB_VID="$SALPA_TEST_USB_VID" \
SALPA_USB_PID="$SALPA_TEST_USB_PID" \
SALPA_USB_SERIAL="$SALPA_TEST_USB_SERIAL" \
python3 tools/build-e000-migration-app.py \
  --build-dir "$SALPA_APPLICATION_BUILD"
```

Bind both clean-tree manifests, the exact partition table, and espflash 4.5.0
into a non-secret package:

```sh
python3 tools/prepare-e000-migration.py \
  --espflash "$ESPFLASH" \
  --bootloader-manifest \
    "$SALPA_BOOTLOADER_BUILD/rissokey-e000-bootloader-build.json" \
  --application-manifest \
    "$SALPA_APPLICATION_BUILD/rissokey-e000-application-build.json" \
  --output-dir "$SALPA_MIGRATION_PACKAGE"
```

None of these commands access a device. The package declares the only allowed
write order: application, erased relocated NVS/PHY range, partition table, then
bootloader. It also contains hash-bound functional legacy recovery images. It
contains no eFuse command.

## Device gate

Put only the intended key into ESP32-S2 ROM download mode and use its explicit
`/dev` path. Two recovery contracts are available.

### Exact recovery with a private backup

Use this default for a device whose current state matters. The backup directory
contains credential secrets; keep it outside Git on encrypted storage with mode
`0700`, do not share it, and do not quote its hashes in public evidence.

First run the read-only backup stage:

```sh
python3 tools/e000-migration-device.py backup \
  --package-dir "$SALPA_MIGRATION_PACKAGE" \
  --backup-dir "$SALPA_PRIVATE_BACKUP" \
  --esptool-python "$ESPRESSIF_PYTHON" \
  --port "$SALPA_ROM_PORT" \
  --acknowledgement CAPTURE_SENSITIVE_FULL_FLASH_BACKUP
```

It requires esptool/espefuse 5.4.0, ESP32-S2, 4 MiB flash, disabled Secure Boot
and flash encryption, and fully available ROM download recovery. It reads the
complete flash and records private hashes for the legacy boot area, legacy
application tail, and `fido_store`. It performs no write, erase, reset, or eFuse
operation.

Only after that stage succeeds, apply the package:

```sh
python3 tools/e000-migration-device.py apply \
  --package-dir "$SALPA_MIGRATION_PACKAGE" \
  --backup-dir "$SALPA_PRIVATE_BACKUP" \
  --esptool-python "$ESPRESSIF_PYTHON" \
  --port "$SALPA_ROM_PORT" \
  --acknowledgement APPLY_REVERSIBLE_E000_MIGRATION
```

The apply stage rereads all 4 MiB and refuses to proceed if the device changed
after backup. It writes and verifies each allowed region separately, confirms
that relocated NVS/PHY sectors are erased, reads `fido_store` back, and compares
it with the private pre-write hash. It deliberately leaves the chip in ROM
download mode so reset and USB observation remain a separate evidence step.

Before any eFuse change, rollback remains available:

```sh
python3 tools/e000-migration-device.py restore \
  --package-dir "$SALPA_MIGRATION_PACKAGE" \
  --backup-dir "$SALPA_PRIVATE_BACKUP" \
  --esptool-python "$ESPRESSIF_PYTHON" \
  --port "$SALPA_ROM_PORT" \
  --acknowledgement RESTORE_FULL_PRE_MIGRATION_FLASH
```

Restore writes and verifies the entire private pre-migration image. The tool
refuses backup, apply, and restore when Secure Boot, flash encryption, or ROM
download restrictions are active.

### Functional recovery for an unused disposable device

This path intentionally captures no full-flash backup. Use it only when losing
the device's current NVS and PHY state is acceptable. Both operations hash
`fido_store` from ephemeral `$TMPDIR` readbacks before and after all writes. The
readbacks and their hashes are neither retained nor written to evidence.

Apply the migration with a new external evidence directory:

```sh
python3 tools/e000-migration-device.py apply-disposable \
  --package-dir "$SALPA_MIGRATION_PACKAGE" \
  --evidence-dir "$SALPA_APPLY_EVIDENCE" \
  --esptool-python "$ESPRESSIF_PYTHON" \
  --port "$SALPA_ROM_PORT" \
  --acknowledgement APPLY_UNUSED_DISPOSABLE_E000_WITHOUT_BACKUP
```

After the physical migration acceptance gates, restore the known legacy image
with another new evidence directory:

```sh
python3 tools/e000-migration-device.py restore-disposable \
  --package-dir "$SALPA_MIGRATION_PACKAGE" \
  --evidence-dir "$SALPA_RESTORE_EVIDENCE" \
  --esptool-python "$ESPRESSIF_PYTHON" \
  --port "$SALPA_ROM_PORT" \
  --acknowledgement RESTORE_UNUSED_DISPOSABLE_LEGACY_WITHOUT_BACKUP
```

The functional restore writes the legacy application first, erases relocated
NVS/PHY, erases legacy NVS/PHY, writes the legacy table, and writes the legacy
bootloader last. It cannot restore any pre-existing NVS configuration. Neither
disposable command formats or writes `fido_store`.

## Physical acceptance

After apply and an explicit reset, record these gates independently:

- USB FIDO HID enumeration with the intended non-production test identity.
- CTAPHID PING and authenticatorGetInfo.
- Successful assertion with an existing disposable-device credential.
- Credential creation, power cycle, and assertion after reconnect.
- Unchanged `fido_store` across apply and restore, proven either against the
  private backup or by ephemeral before/after comparison.
- Full-flash or functional legacy rollback, followed by legacy USB enumeration
  and a legacy credential assertion when a disposable credential was created.

The disposable ESP32-S2 passed the migration and functional rollback gate on
2026-09-03 with package source commit `612b0a2`. Apply and restore both verified
that `fido_store` stayed unchanged. The migration and legacy layouts each
booted, answered CTAPHID PING and GetInfo, and verified an assertion signature
with the same test credential. The user reported the intervening reset, but the
host did not observe its USB disconnect, so the evidence records that detail
instead of claiming an observed power cycle. No full backup or eFuse operation
occurred, and exact prior NVS restoration was not tested.

The profile status is `device-test-passed`, but it remains ineligible for
release candidates. This gate clears only the partition-layout prerequisite
for signed A/B recovery work.
