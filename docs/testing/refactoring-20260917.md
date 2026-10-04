# Refactoring validation, 2026-09-17

Four local commits separate responsibilities while preserving the existing
command line, protocol, package formats and acceptance checks:

| Change | Development commit | Result |
| --- | --- | --- |
| Protected package validation and manifest construction | `15668a6` | Pure validation functions and complete schema-2 manifest regression fixture captured from `f23bf0a` |
| Installed image verification | `561f2fc` | Shared image parser and `ImageReader` with only read and RSA-verification methods; verifier tests use a backend with no write or activation interface |
| S2 vendor dispatch | `05273bf` | Runtime keeps resource and buffer ownership, zeroization and FIDO confirmation; diagnostic evaluation order, reply selection and physical-presence retry are preserved |
| macOS helper source split | `a4d7e27` | 66 declarations preserved; installation and tests use one explicit production source list |

These commit identifiers belong to the development history. The generated
source mirror records its own source provenance separately.

## Verified on the host

The [machine-readable record](refactoring-20260917.json) binds the modified
implementation files to SHA-256 digests and lists the target commands/results.

- 148 Rust host tests, 31 persistent-state tests, 11 storage-fault tests and
  106 Python tests passed.
- All ten compile-only firmware profiles passed release builds and Clippy
  with warnings denied. The matrix now includes unencrypted signed A/B USB
  updates, covering vendor dispatch without protected diagnostic features.
- Protected ELF/PMS checks passed for the normal and maintenance profiles.
  A separately built normal runtime retained the baseline PMS boundaries,
  handler address, 149,332-byte stack reservation and 50,240-byte static
  `main` frame allocation. Peak stack consumption was not measured.
- The macOS fixture runner passed Espressif AES-XTS vectors, password
  derivation, authenticated-backup rejection cases, RSA-PSS verification,
  separate-process attestation restoration and exact staging checks.
  It also compiled the production entry and checked its empty-command error
  without requesting Keychain access.

## Reproduction

Use the pinned tools and external build/cache directories described in
[getting started](../getting-started.md). Run:

```sh
cargo +1.97.0 test --lib --locked --target aarch64-apple-darwin --no-default-features
./tools/test-storage-faults
./tools/test-persistent-state
python3 -B -m unittest discover -s tests -p 'test_*.py'
python3 -B tools/check-firmware-builds.py --check all --build-dir "$TMPDIR/salpa-refactor-builds"
python3 -B tools/macos-key-helper/test-crypto.py
python3 -B scripts/check_public_tree.py source
```

Set `CARGO_TARGET_DIR` outside the repository and select the actual host triple
on other hosts. The firmware build directory must not already exist.
The helper checks require macOS. The ordinary compiler and Espressif compiler
remain separate toolchains.

## Acceptance limits

No helper was installed, no operational keys were used and no physical device
was accessed. Real Keychain ACL/approval checks and firmware USB, presence,
update, persistence and browser checks remain separate acceptance steps.
The earlier [S2 hardware results](esp32s2-results.md) retain their original
signed-image scope. This refactoring does not extend that acceptance to a new
firmware image or change any device-action authorization.
