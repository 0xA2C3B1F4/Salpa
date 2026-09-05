# Signed A/B update and recovery gate

This gate tests signed application selection, first-boot confirmation, rollback,
and rejection of an image signed by another key on a disposable ESP32-S2. It
does not enable hardware Secure Boot, flash encryption, or any eFuse. Physical
replacement of the bootloader can therefore replace the development trust
anchor; that threat remains for the later hardware-enforcement gate.

## Layout and trust boundary

`partitions-ab.csv` keeps `fido_store` at `0x3E0000+0x20000` and uses:

- `otadata` at `0xF000+0x2000`
- `ota_0` at `0x20000+0x1E0000`
- `ota_1` at `0x200000+0x1E0000`

The custom ESP-IDF bootloader pins the ESP Secure Boot V2 digest of one
RSA-3072 public key and verifies every application slot before loading it. The
private test keys, build trees, signed images, and device evidence remain
outside Git. The package contains only the trusted public key.

This reversible development profile sends bootloader diagnostics through the
ESP32-S2 native USB CDC console. Production console policy remains part of the
later hardware-enforcement gate.

The Rust application changes an ESP-IDF-compatible `PENDING_VERIFY` entry to
`VALID` only after a successful CTAP2 response. It also checks that the active
slot's application descriptor has the running build's exact version string.
That prevents a trusted fallback image from confirming a rejected candidate.
If confirmation does not happen, the ESP-IDF rollback state machine marks the
candidate `ABORTED` on the next reset and loads the previous valid slot.

The original physical gate stages images through the ROM downloader. A separate
runtime path now implements signed delivery through CTAPHID vendor command
`0x51`, fresh physical approval, inactive-slot writes, readback hashing,
signature verification, and activation-last. A disposable ESP32-S2 passed the
complete success, power-cut, wrong-key rejection, reconnect persistence, and
candidate rollback gates without eFuse changes. See
[`usb-signed-update.md`](../guides/usb-signed-update.md).

## Host preparation

Use pinned ESP-IDF v6.1 commit
`fff9895c82d744c7237be8847347bdd1b07c6643`, `esptool` 5.4.0, and
`espflash` 4.5.0. Build only from a clean commit and place every output in a
new directory outside the repository.

Generate two disposable RSA-3072 signing keys outside Git. One is the trusted
development key; the second signs the negative-test image. Export public-only
PEM files, then build the bootloader and three application variants:

```sh
python3 tools/build-signed-ab-bootloader.py \
  --idf-path "$IDF_PATH" \
  --idf-tools-path "$IDF_TOOLS_PATH" \
  --public-key "$RISSO_KEY_TRUSTED_PUBLIC_KEY" \
  --build-dir "$RISSO_KEY_AB_BOOTLOADER_BUILD"

for variant in base failure success; do
  python3 tools/build-signed-ab-app.py \
    --variant "$variant" \
    --update-key-digest "$RISSO_KEY_TRUSTED_PUBLIC_KEY_DIGEST" \
    --secure-version 0 \
    --build-dir "$RISSO_KEY_AB_BUILD_ROOT/$variant"
done

python3 tools/prepare-signed-ab-package.py \
  --espflash "$RISSO_KEY_ESPFLASH" \
  --esptool-python "$RISSO_KEY_ESPTOOL_PYTHON" \
  --bootloader-manifest "$RISSO_KEY_AB_BOOTLOADER_MANIFEST" \
  --base-manifest "$RISSO_KEY_AB_BASE_MANIFEST" \
  --failure-manifest "$RISSO_KEY_AB_FAILURE_MANIFEST" \
  --success-manifest "$RISSO_KEY_AB_SUCCESS_MANIFEST" \
  --trusted-public-key "$RISSO_KEY_TRUSTED_PUBLIC_KEY" \
  --untrusted-private-key "$RISSO_KEY_UNTRUSTED_PRIVATE_KEY" \
  --untrusted-public-key "$RISSO_KEY_UNTRUSTED_PUBLIC_KEY" \
  --output-dir "$RISSO_KEY_AB_PACKAGE"
```

For the separate GPIO16 user-presence gate, add
`--non-strapping-user-presence` to all three application builds and pass
`--security-profile wemos-s2-mini-non-strapping-up-test` to the package
command. The partition layout, signing boundary, and no-eFuse device flow stay
the same.

USB VID, PID, and serial values are required by the application builder but
are intentionally absent from its evidence manifest. Never use production
signing material for this gate.

## Physical sequence

Run only on a disposable 4 MiB ESP32-S2 whose Secure Boot, flash encryption,
and ROM-download restrictions are still disabled. The install acknowledgement
also records that the operator deliberately chose the unused-device path with
no full-flash backup.

1. Install the base image in ROM download mode. The tool erases and verifies
   only the bootloader, A/B metadata/data, and application regions. It hashes
   `fido_store` before and after and never writes it.
2. Reset and complete GetInfo. This establishes `ota_0` as `VALID`.
3. Stage the trusted failure image. It must boot once, then roll back after the
   next reset because that image cannot confirm itself.
4. Stage the trusted success image. After one successful CTAP2 request, it must
   remain active across another reset.
5. Stage the image signed by the second key. The bootloader must reject it,
   load the prior valid slot, and mark the candidate `ABORTED` on the following
   reset.
6. Capture read-only otadata and eFuse summaries after each decisive state and
   recheck USB FIDO plus any disposable credential-persistence fixture.

The device tool requires a new external evidence directory for each operation:

```sh
python3 tools/signed-ab-device.py install \
  --package-dir "$RISSO_KEY_AB_PACKAGE" \
  --evidence-dir "$RISSO_KEY_AB_EVIDENCE/install" \
  --esptool-python "$RISSO_KEY_ESPTOOL_PYTHON" \
  --port "$RISSO_KEY_ROM_PORT" \
  --acknowledgement INSTALL_SIGNED_AB_TEST_WITHOUT_BACKUP
```

Use `stage --image failure`, `stage --image success`, or
`stage --image untrusted` with the acknowledgement printed by the tool. Use
`status` for read-only state capture. None of these operations calls
`espefuse burn-efuse` or enables an irreversible protection.

## Acceptance

Host compilation alone proves neither bootability nor recovery. This gate
passes only when the physical evidence shows the expected failure rollback,
success persistence, untrusted-signature rejection, unchanged credential-store
hash, working USB FIDO, and unchanged eFuse security fields. Hardware Secure
Boot, encrypted credential storage, and the exact irreversible eFuse plan
remain blocked afterward. GPIO16 user-presence acceptance passed separately;
see `docs/development/non-strapping-user-presence.md`.

The disposable ESP32-S2 gate passed on 2026-09-04 with source commit
`0f5bd51130c49c33d94a2cb95de93e4107653930`. The run used one package whose
bootloader and all application manifests came from that commit. The redacted,
hash-bound result is in
[`docs/evidence/signed-ab-esp32s2-0f5bd51.json`](../evidence/signed-ab-esp32s2-0f5bd51.json).

Trusted firmware signing now uses the local macOS Keychain helper and requires fresh owner authentication. See [key management](../guides/key-management.md). The untrusted key remains an isolated negative-test fixture.
