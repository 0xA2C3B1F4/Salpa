# Contributing

Keep changes within the [implementation plan](../docs/implementation-plan.md).
SoloKeys and Trussed own FIDO2 semantics and credential cryptography.

## Public mirror

Release source is exported from an explicit file allowlist and bound to file
hashes in `source-export.json`. Open an issue before a large change. The
maintainer integrates accepted changes and regenerates the export and provenance.
Dependency-update proposals follow the same process.

## Required checks

Install the pinned Python dependencies and host Rust version, then follow
[Getting started](../docs/getting-started.md). Run the Python suite, formatting,
Rust host tests, storage-fault tests, persistent-state tests, and policy checks.
Changes to export policy must also pass these tests from a fresh exported tree.
Changes to firmware must pass the affected profiles in
`tools/check-firmware-builds.py`. macOS helper changes require its fixture suite.

CI runs these checks with public fixtures. Hardware behavior and Keychain
access-control behavior need their separate acceptance tests. Do not use an
enrolled account key as a disposable regression device.

Never submit private keys, PINs, tokens, device serials, credential IDs,
account identifiers, raw WebAuthn packets, firmware images, or raw device logs.
Do not include generated development attestation keys even in test fixtures.

## Licensing

By contributing, you agree that your contribution is licensed under the MIT
License. Do not copy code whose license is incompatible with this repository.
Keep upstream copyright and license notices with vendored changes.
