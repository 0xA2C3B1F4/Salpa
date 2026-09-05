# Secure Boot V2 build gate

This gate proves that the ESP32-S2 firmware can be paired with a custom
ESP-IDF Secure Boot V2 bootloader and that externally signed images can be
verified. It does not authorize flashing, booting the image, or writing eFuses.

## Pinned inputs

- ESP-IDF v6.1 at commit `fff9895c82d744c7237be8847347bdd1b07c6643`
- `esptool` and `espsecure` 5.4.0
- ESP32-S2 Secure Boot V2 with RSA-3072 signatures
- DIO flash mode, 40 MHz flash frequency, and 4 MiB flash size
- External signing; the source and build hosts do not require a production
  private key

The build-only configuration is in
`security/esp-idf-bootloader/sdkconfig.defaults.esp32s2`. It enables hardware
Secure Boot V2 in the generated bootloader but leaves signing to an external
step. It explicitly leaves flash encryption disabled. If a correctly signed
derivative is booted, ESP-IDF can irreversibly program security eFuses. Treat
every generated bootloader as hazardous even though the build command itself
does not access a device.

## Measured host result

On 2026-09-03, the pinned ESP-IDF checkout built the configuration as an
unsigned 36,864-byte bootloader. The default partition-table offset `0x8000`
was too small. Moving the build-spike offset to `0xE000` left 16 KiB before the
table while preserving the current application start at `0x10000`.

An ephemeral CI-only RSA-3072 key signed both the secure-padded Rust application
image and the custom bootloader. `espsecure` 5.4.0 verified both signatures with
the corresponding public key. No image was flashed and no eFuse command ran.
The CI key is not a provisioning key and must never be reused on hardware.

Build the unsigned bootloader only from a clean source commit and a new external
build directory:

```sh
python3 tools/build-secure-boot-v2-bootloader.py \
  --idf-path "$IDF_PATH" \
  --build-dir "${TMPDIR%/}/rissokey-secure-boot-v2-build"
```

The tool rejects the wrong ESP-IDF commit, an in-repository build directory,
unexpected security settings, a dirty source tree, and a build that modifies
the source tree. Its JSON evidence states explicitly that no flash or eFuse
operation was performed.

Verify an externally signed image with a PEM public key and pinned tooling:

```sh
python3 tools/verify-secure-boot-v2-signature.py \
  --image "$RISSO_KEY_SIGNED_IMAGE" \
  --public-key "$RISSO_KEY_SIGNING_PUBLIC_KEY" \
  --output "$RISSO_KEY_SIGNATURE_EVIDENCE"
```

The verifier refuses private PEM material and records only file names, hashes,
sizes, and tool versions. Production signing belongs in an isolated signer or
HSM workflow, not in this repository or its CI.

## Remaining device gates

- The disposable key passed the reversible `0xE000` apply, FIDO, credential,
  and functional legacy rollback gate without eFuse changes. Exact commands and
  evidence limits are recorded in `docs/development/e000-migration.md`.
- The signed A/B source, packaging, rollback, confirmation, and wrong-key
  rejection gates passed on disposable hardware; see
  `docs/development/signed-ab-update.md`.
- The release flash-encryption storage backend compiles, but encrypted boot,
  recovery, and credential persistence have not run on hardware; see
  `docs/development/flash-encryption-storage.md`.
- The protected source selects external GPIO16 for user presence. Its physical
  gate and rejection of the GPIO0 BOOT button passed on disposable hardware;
  see `docs/development/non-strapping-user-presence.md`.
- Review an exact eFuse plan, then capture pre-write and post-write readback.

Until all remaining gates pass, `wemos-s2-mini-protected-prototype` remains
blocked and no RissoKey build is release eligible.
