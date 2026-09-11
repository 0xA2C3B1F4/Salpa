# Salpa

Salpa is experimental USB FIDO2 security-key firmware for the WEMOS S2 Mini
(ESP32-S2), built around the SoloKeys/Trussed authenticator stack. The tested
protected profile uses an external GPIO16 button for physical user presence.
An ESP32-S3 port is under development; complete FIDO operation on S3 hardware
has not yet been accepted.

The project explores practical account authentication, protected credential
storage, physically approved firmware updates, and recoverable provisioning.
The protected S2 configuration has completed Secure Boot V2, flash-encryption,
signed USB-update, rollback, and encrypted recovery tests on hardware. The
subsequent hardening round tested a hardware firmware floor of 5 and closed
USB ROM access while preserving normal FIDO and signed updates.

## What works

| Capability | Current evidence |
| --- | --- |
| USB FIDO2 | CTAPHID, ES256 credentials, PIN, discoverable credentials, and credential management tested on S2 development hardware |
| Protected S2 runtime | Secure Boot V2, release-mode flash encryption, disabled JTAG, and a dedicated GPIO16 presence button |
| PMS RAM protection | Code write protection and data execution restrictions; five fixed access checks passed on an instrumented S2 test image |
| Credential persistence | The same credential authenticated after a power cycle, signed USB update, rollback, and encrypted ROM recovery |
| Firmware updates | Fresh physical approval, signature and readback verification, inactive-slot installation, and activation last |
| Final S2 hardening | Epoch-4 application rejected at hardware floor 5; USB ROM entry blocked; FIDO, updates and fallback retested afterward |
| Browser interoperability | Security-key enrollment and authentication with PIN and physical presence, manually tested |
| Maintainer key custody | Local macOS Keychain helper, interactive approval, separate key records, and encrypted backup/restore tooling |
| ESP32-S3 | Build and port work; complete FIDO operation on S3 hardware is not yet accepted |

See [testing](docs/testing/README.md) for reproducible checks and the
[ESP32-S2 results](docs/testing/esp32s2-results.md) for hardware configurations,
measured results and manual browser test results. The
[final hardening report](docs/testing/esp32s2-final-hardening.md) distinguishes
USB ROM-denial evidence from untested UART and physical-attack paths.

## Security scope

These protections address specific threats. WebAuthn binds authentication to
the relying party. The tested protected profile verifies its boot chain and
encrypts credential storage. PIN checks and a fresh button press authorize
credential operations according to the FIDO protocol. Signed updates and
tested A/B fallback protect application maintenance.

Credential operations currently run in the main MCU. Flash encryption does
not isolate decrypted keys from compromised authorized firmware. The current
hardware has no separate secure element, and its resistance to fault injection,
side-channel analysis, and invasive attacks has not been independently assessed.
A secure element or secure MCU is a future design option for stronger key
isolation and physical protection, with integration and evaluation still needed.

The development and protected profiles have different properties. The final
tested S2 profile closes ROM download and loses ROM-based recovery. Its trusted
bootloader enforces application security epoch 5. This does not establish
freshness of encrypted FIDO state or prevent every physical bootloader replay.
A/B fallback requires a working boot chain and usable metadata. Salpa is not
FIDO Certified.
Read the [security model](docs/design/security-model.md) and [roadmap](docs/roadmap.md).

Do not use Salpa as an account's only login or recovery method. Set up an
independent alternative and test it with Salpa unplugged. If the device
locks or fails, you may need to register a replacement security key with each
service. A device backup does not guarantee that its credentials can be moved
to another device.

## What you need

To try the protected ESP32-S2 profile on hardware:

- A WEMOS S2 Mini board with an ESP32-S2 and 4 MB flash.
- A USB data cable and a computer with a native USB connection to the board.
- A normally open momentary button connected between GPIO16 and GND, with
  suitable wires or headers. The protected profile uses this external button;
  the earlier development profile uses the onboard GPIO0/BOOT button.
- The build tools and staged setup described in
  [getting started](docs/getting-started.md) and
  [installing and updating](docs/guides/installing-and-updating.md).

Use a separate board for first provisioning experiments. The current release
provides source rather than a ready-to-install firmware download. Host tests
and compile checks can also be run without a board.

## Build and test

Start with [getting started](docs/getting-started.md). It covers the pinned Rust
and Python tools, host tests, and public fixture builds that require no device
or operational keys. Build outputs stay outside the source tree.

For implementation details, see the [architecture](docs/design/architecture.md),
[dependency spike](docs/development/dependency-spike.md),
[signed USB updates](docs/guides/usb-signed-update.md), and
[firmware signing and maintainer key management](docs/guides/key-management.md).
The key-management guide is for publishers and builders managing their own
keys. Provisioning and device writes are
separate operations with explicit prerequisites and physical approval.

## Installation and updates

There is no unified guided or graphical installer yet. The current tools handle
separate preparation, provisioning and update stages.

For a new protected S2, identify the board and security profile, establish key
custody and verified backups, then build the bootloader and application
manifests. `tools/prepare-protected-package.py` signs and encrypts the package
without writing the board. Device installation then follows separate approved
security, ciphertext/readback, storage, attestation and runtime acceptance
stages. Final ROM closure is a later hardening decision.

For a working protected S2 runtime with signed USB update support, obtain a
normal application already signed by the
publisher whose root the device trusts, then transfer `runtime-usb-signed.bin`
with `tools/salpa-usb-ota.py` and approve installation with a fresh GPIO16
press. Ordinary users do not need private firmware keys or the macOS key
helper for login or update installation. A builder managing their own signing
root also performs the publisher's signing step. Reboot, confirm normal FIDO
operation and check an existing credential afterwards. USB updates use signed
plaintext application images, not offset-encrypted factory-install images.

`tools/signed-ab-device.py install` belongs to the unencrypted A/B development
test profile. It is not the protected-device installer.

Follow [installing and updating](docs/guides/installing-and-updating.md) for the
full sequence, prerequisites, commands and links to the correct procedure.

## Repository layout

| Directory | Contents |
| --- | --- |
| `src/` | Firmware, USB transport and ESP32 platform integration |
| `tools/` | Build, update, recovery and local key-management tools |
| `tests/` | Host regressions and storage fault models |
| `security/`, `policy/` | Bootloader inputs, device profiles and release checks |
| `docs/` | Design, guides, implementation plans and test results |
| `third_party/` | Pinned upstream sources and their licenses |

The [documentation index](docs/README.md) is the entry point for detailed material.

## Source release workflow

The current version is an experimental source-only alpha candidate. It does
not include ready-to-install firmware or provisioned device images.

This repository is a source mirror generated from an explicit allowlist.
Each export includes `source-export.json` with the source commit and file
SHA-256 digests. The export is checked for required source files, local document
links, and selected sensitive-content patterns, then compiled and tested in CI.
Operational keys, backups, device-specific images, and raw device logs are not
included in the source export.

See [contributing](CONTRIBUTING.md) for the mirror workflow and
[SECURITY.md](SECURITY.md) for private vulnerability reporting. Salpa's own
code is [MIT licensed](LICENSE); upstream code retains its
[licenses and notices](docs/third-party-notices.md). The [implementation plan](docs/implementation-plan.md) describes the product
scope and next acceptance steps.
