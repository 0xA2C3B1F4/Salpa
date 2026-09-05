# ESP32-S2 protected-prototype eFuse plan

This is a reusable provisioning template for a disposable WEMOS S2 Mini, with
a blocked final hardening stage. The previously accepted device is now enrolled
and must not be reprovisioned through this template. The plan is deliberately
marked `draft-unapproved`. Committing or validating it is not authorization to
burn an eFuse, flash a protected image, erase a device, or boot a configuration
that enables security features on first boot.

The machine-readable source is
[`policy/esp32s2-protected-efuse-plan.json`](../../policy/esp32s2-protected-efuse-plan.json).
It fixes the target, tool versions, key-block allocation, operation order,
readback contracts, and three separate irreversible authorization boundaries.
The validator never emits a burn command:

```sh
python3 scripts/check_efuse_plan.py --self-test
```

An `espefuse 5.4.0` JSON summary captured outside Git can be checked without
printing its contents:

```sh
python3 scripts/check_efuse_plan.py \
  --summary "$SUMMARY_JSON" \
  --state pristine
```

The final full readback gate also binds the readable eFuse digest to the
expected 32-byte public Secure Boot digest:

```sh
python3 scripts/check_efuse_plan.py \
  --summary "$SUMMARY_JSON" \
  --state provisioned_before_rom_lockdown \
  --secure-boot-digest "$SECURE_BOOT_DIGEST"
```

The summary can contain device-specific data, so it stays outside Git and
public evidence. Restricted download removes normal `espefuse` access, while
complete ROM closure removes the ROM maintenance channel. Final verification
must follow the chosen mode and tested transport. See the
[hardening design](../plans/esp32s2-hardening.md).

## Fixed choices

- `BLOCK_KEY0` holds one unique 32-byte AES-XTS flash-encryption key with
  `XTS_AES_128_KEY` purpose. The key is read- and write-protected.
- `BLOCK_KEY1` holds the 32-byte digest for one prototype RSA-3072 signing key
  with `SECURE_BOOT_DIGEST0` purpose. The public digest remains readable and is
  write-protected.
- Secure Boot digest slots 1 and 2 are revoked. Aggressive automatic revocation
  remains disabled for the prototype.
- Flash encryption uses release mode (`SPI_BOOT_CRYPT_CNT=7`). JTAG, legacy SPI
  boot, download-mode caches, and download-mode manual encryption are disabled.
  Espressif's summary still labels the fully consumed three-bit counter as
  writable; the exact raw value is therefore the fail-closed check for it.
- Full ROM download remains available in the accepted checkpoint. The final
  stage has no burn operations until recovery and anti-downgrade design gates
  pass. `ENABLE_SECURITY_DOWNLOAD` is restricted maintenance, not complete
  closure. Shared eFuse write protection must preserve future security epochs.

The existing flash key is handled outside both repositories and retained for
current recovery. Its later retention or deletion is a separate decision after
the final recovery model and required backups are verified. The signing private
key also remains outside Git. Public source and evidence may contain public-key digests, but not
keys, device identifiers, raw eFuse summaries, or sensitive packet logs.

## Ordered gates

1. Build, sign, verify, and encrypt the complete package for its final flash
   offsets. Keep all output and secret material outside Git.
2. Capture a fresh read-only chip identity and eFuse summary. The validator must
   accept the `pristine` profile. Erase only the disposable target.
3. With fresh explicit authorization, program the flash key and release-mode
   flash-encryption fields. This also permanently disables JTAG.
4. Write the already prepared ciphertext and verify raw readback before Secure
   Boot is enabled.
5. With a second fresh explicit authorization, program the public signing-key
   digest, enable Secure Boot V2, revoke unused digest slots, and write-protect
   `RD_DIS`.
6. Prove encrypted boot, USB FIDO, signed A/B success and rollback, fresh
   encrypted credential-store provisioning, power-cycle persistence, and the
   signed encrypted recovery path. Capture the final full readback outside Git;
   it must match `provisioned_before_rom_lockdown`.
7. Complete the [final hardening prerequisites](../plans/esp32s2-hardening.md), then
   prepare a device-specific ROM policy and exact field sequence for fresh
   explicit authorization. Verify normal signed updates and the selected ROM
   behavior afterwards. Key retention is a separate step; this template never
   instructs automatic deletion.

Power must remain stable during every irreversible stage. A failure stops the
procedure; it never advances to the next stage based only on tool exit status.

## Preflight result

On 2026-09-04 gate 1 and the read-only portion of gate 2 passed for source
commit `fe17f88`. The protected package was built using clean, exactly pinned
ESP-IDF sources. Its 15 manifest-bound file hashes, signatures, and
final-offset ciphertext round trips passed. The package includes a
same-secure-version rollback-failure fixture outside every initial-install and
recovery set. A fresh device summary matched the `pristine` profile, and the
device returned to normal FIDO operation after the read-only reset. No flash or
eFuse write was performed.

The redacted record is
[`docs/evidence/protected-preflight-esp32s2-fe17f88.json`](../evidence/protected-preflight-esp32s2-fe17f88.json).
At that checkpoint, fresh authorization for gate 3 had not been requested or
granted. The checked-in plan remains a `draft-unapproved` template; it is not
the record of per-device authorizations.

On 2026-09-05, source `0d295e8` rebuilt the complete protected package with the
audited update fixes and shared reply-completion module. Independent checks
verified all 15 manifest-bound files, signatures, final-offset decryption, and
the normal and rollback USB images against both encrypted slots. The existing
signing root, flash key, and USB identity were reused without publishing their
private values. The redacted continuation record is
[`docs/evidence/protected-preflight-esp32s2-0d295e8.json`](../evidence/protected-preflight-esp32s2-0d295e8.json).

A fresh read-only check matched the authorized target and every saved eFuse
value and protection from the completed first stage. Flash encryption and JTAG
disablement were active; Secure Boot and secure ROM download were still
disabled at that read-only checkpoint. That check did not reset or write the
device.

With subsequent explicit device authorization on 2026-09-05, the replacement
initial bootloader, partition table, and storage provisioner were installed
without reset. Raw readback matched all 160 KiB of written sectors, including
the partition table's erased sector tail. This was a verification of the
written sectors, not a new whole-flash readback.

Only after that match, the public signing digest was programmed into
`BLOCK_KEY1` with `SECURE_BOOT_DIGEST0` purpose, Secure Boot V2 was enabled,
unused slots 1 and 2 were revoked, and `RD_DIS` was write-protected. The complete
eFuse profile and public digest matched the plan. Independent ROM security
information confirmed Secure Boot and flash encryption enabled. The evidence is
[`docs/evidence/secure-boot-v2-esp32s2-0d295e8.json`](../evidence/secure-boot-v2-esp32s2-0d295e8.json).

At that checkpoint the device remained in ROM mode without a reset. The eFuse
profile name `provisioned_before_rom_lockdown` described its security fields,
without asserting credential readiness. The later [protected acceptance](../evidence/protected-ota-esp32s2-20260905.json)
records normal boot, credential persistence, signed USB update, rollback and
ROM recovery. Final ROM policy remains open.

The build-only inputs for the first gate are
`sdkconfig.defaults.esp32s2-protected-external`,
`tools/build-signed-ab-bootloader.py --protected-external`, and
`tools/build-protected-app.py`. The application builder produces separate
normal-runtime, deliberate rollback-failure, and one-shot storage-provisioner
ELFs. In the protected build all three use GPIO16 for confirmation; the
provisioner remains a separate image and cannot be selected by a normal runtime
build. The rollback fixture differs from the normal runtime only by the
test-only feature that withholds first-boot confirmation.

Building the storage provisioner also requires the explicit host-build
acknowledgement `RISSO_KEY_PROVISIONING_ACK=ERASE_FIDO_STORE`. This permits
compilation only; it does not authorize running the image or formatting
physical storage.

The storage provisioner does not install attestation. Before an authorized
erase, prove that the original FIDO attestation key and certificate can be
recovered. Restore the same pair into the initialized encrypted store before
normal-runtime acceptance. A two-pulse storage result is insufficient for
FIDO readiness. See [attestation recovery](../guides/attestation-recovery.md).

`tools/prepare-protected-package.py` consumes clean-commit build manifests and
external prototype keys. It signs the bootloader and all three applications
before AES-XTS-encrypting the bootloader, partition table, runtimes, and
provisioner for their exact destination offsets. It decrypts every ciphertext
back in scratch and verifies each executable signature before emitting a
hash-bound recovery manifest. Neither secret key is copied into the package,
the rollback fixture is excluded from install and recovery sets, and
`fido_store` and `otadata` images are deliberately omitted.

Package schema 2 names the normal install set
`runtime_with_existing_attestation`, replacing `runtime_after_provisioning`.
Its explicit preconditions require the original identity in encrypted storage
and boot metadata selecting `ota_0`. The recovery set also writes only `ota_0`;
verify the active slot before choosing it. These are preparation records, not
proof of on-device identity restoration or authorization to install.

## Licensing boundary

The plan, validator, and RissoKey integration code are MIT-licensed. Espressif
ESP-IDF and its tools are external Apache-2.0 dependencies and are not copied
into this repository. The pinned ESP-IDF commit and tool versions are inputs to
the build and validation gates. SoloKeys, Trussed, and other vendored sources
retain the licenses documented in `docs/third-party-notices.md`.

References:

- [Espressif security-feature enablement workflow](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s2/security/security-features-enablement-workflows.html)
- [ESP32-S2 flash encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s2/security/flash-encryption.html)
- [ESP32-S2 Secure Boot V2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/security/secure-boot-v2.html)
