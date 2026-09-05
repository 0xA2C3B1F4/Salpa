# RissoKey

RissoKey is an experimental USB FIDO2 security key built around the
SoloKeys/Trussed authenticator stack. The working prototype uses an ESP32-S2;
an ESP32-S3 port is under development.

The project explores practical account authentication, protected credential
storage, physically approved firmware updates, and recoverable provisioning.
The protected S2 configuration has completed Secure Boot V2, flash-encryption,
signed USB-update, rollback, and encrypted recovery tests on hardware.

## What works

| Capability | Current evidence |
| --- | --- |
| USB FIDO2 | CTAPHID, ES256 credentials, PIN, discoverable credentials, and credential management tested on S2 development hardware |
| Protected S2 runtime | Secure Boot V2, release-mode flash encryption, disabled JTAG, and a dedicated GPIO16 presence button |
| Credential persistence | The same credential authenticated after a power cycle, signed USB update, rollback, and encrypted ROM recovery |
| Firmware updates | Fresh physical approval, signature and readback verification, inactive-slot installation, and activation last |
| Browser interoperability | OpenAI enrollment using Chrome and subsequent Safari authentication with PIN and button, reported by the protected-device owner |
| Maintainer key custody | Local macOS Keychain helper, interactive approval, separate key records, and encrypted backup/restore tooling |
| ESP32-S3 | Build and port work; complete FIDO operation on S3 hardware is not yet accepted |

See the [evidence index](docs/evidence/README.md) for dates, configurations, and
which results are host tests, physical tests, or owner reports. OpenAI is an
interoperability target; RissoKey has no OpenAI affiliation or endorsement.

## Security scope

These protections address specific threats. WebAuthn binds authentication to
the relying party. The tested protected profile verifies its boot chain and
encrypts credential storage. PIN checks and a fresh button press authorize
credential operations according to the FIDO protocol. Signed updates and a
tested recovery path protect firmware maintenance.

Credential operations currently run in the main MCU. Flash encryption does
not isolate decrypted keys from compromised authorized firmware. The current
hardware has no separate secure element, and its resistance to fault injection,
side-channel analysis, and invasive attacks has not been independently assessed.
A secure element or secure MCU is a future design option for stronger key
isolation and physical protection, with integration and evaluation still needed.

The development and protected profiles have different properties. The accepted
protected checkpoint retains full ROM download for recovery; it is not a final
production configuration. A/B rollback is a recovery feature, not a claim of
hardware-enforced anti-downgrade or storage-replay resistance. RissoKey is not
FIDO Certified and should not be the only way to access an important account.
Read the [security model](docs/design/security-model.md) and [roadmap](docs/roadmap.md).

## Build and test

Start with [getting started](docs/getting-started.md). It covers the pinned Rust
and Python tools, host tests, and public fixture builds that require no device
or operational keys. Build outputs stay outside the source tree.

For implementation details, see the [architecture](docs/design/architecture.md),
[dependency spike](docs/development/dependency-spike.md),
[signed USB updates](docs/guides/usb-signed-update.md), and
[key management](docs/guides/key-management.md). Provisioning and device writes are
separate operations with explicit prerequisites and physical approval.

## Repository layout

| Directory | Contents |
| --- | --- |
| `src/` | Firmware, USB transport and ESP32 platform integration |
| `tools/` | Build, update, recovery and local key-management tools |
| `tests/` | Host regressions and storage fault models |
| `security/`, `policy/` | Bootloader inputs, device profiles and release checks |
| `docs/` | Design, guides, implementation plans and evidence |
| `third_party/` | Pinned upstream sources and their licenses |

The [documentation index](docs/README.md) is the entry point for detailed material.

## Source release workflow

This source mirror is currently private for owner review. Publication and the
first alpha release are pending that review.

This repository is a source mirror generated from an explicit allowlist.
Each export includes `source-export.json` with the source commit and file
SHA-256 digests. The export is checked for required source files, local document
links, and selected sensitive-content patterns, then compiled and tested in CI.
Operational keys, backups, device-specific images, and raw device logs are not
published. The first alpha release contains source only.

See [contributing](.github/CONTRIBUTING.md) for the mirror workflow and
[SECURITY.md](.github/SECURITY.md) for private vulnerability reporting. RissoKey's own
code is [MIT licensed](LICENSE); upstream code retains its
[licenses and notices](docs/third-party-notices.md). The [implementation plan](docs/implementation-plan.md) describes the product
scope and next acceptance steps.
