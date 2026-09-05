# Documentation

Start with [getting started](getting-started.md) to build and test the source
without a device or operational keys. The [implementation plan](implementation-plan.md)
defines the scope and acceptance steps; the [roadmap](roadmap.md) describes
remaining work.

## Design

- [Architecture](design/architecture.md): upstream FIDO stack and platform boundaries.
- [Security model](design/security-model.md): implemented protections, threats and limits.
- [Dependency security](design/dependency-security.md) and [third-party notices](third-party-notices.md).

## Maintenance guides

- [Installing and updating](guides/installing-and-updating.md): choose the device workflow; users install an already signed update.
- [Signed USB updates](guides/usb-signed-update.md): user installation, protocol and maintainer build details.
- [Firmware signing and maintainer key management](guides/key-management.md): for publishers and builders managing signing keys, Keychain access and backups.
- [Attestation preservation and recovery](guides/attestation-recovery.md).

## Further hardening

- [ESP32-S2 hardening design](plans/esp32s2-hardening.md): ROM policy, security epochs and recovery dependencies.
- [Release hardening](plans/release-hardening.md): remaining production requirements.

## Evidence and development records

The [evidence index](evidence/README.md) separates host tests, physical tests and
owner reports. [Change history](changelog.md) records source milestones.

`development/` contains the technical bring-up and migration records behind
the current design: [dependency spike](development/dependency-spike.md),
[USB](development/usb-bringup.md), [CTAPHID](development/ctaphid-bringup.md),
[platform services](development/platform-services.md),
[dedicated presence input](development/non-strapping-user-presence.md),
[partition migration](development/e000-migration.md),
[Secure Boot](development/secure-boot-v2.md),
[signed A/B boot](development/signed-ab-update.md),
[flash encryption](development/flash-encryption-storage.md),
[provisioner diagnosis](development/provisioner-diagnostics.md), and the
[unapproved eFuse template](development/esp32s2-efuse-plan.md).
These records retain their original test scope and do not replace current
maintenance instructions or authorize a device operation.
