# Narrow portability patches

This directory contains four pinned upstream crates with narrow local changes.
The application selects ESP32-S2 through `esp-hal`, which enables
`portable-atomic`'s single-core Xtensa implementation. The vendored libraries do
not enable that unsafe platform promise themselves.

Sources:

- `interchange` 0.3.2, crates.io package, upstream commit
  `4a0eb996710face821ee7c643462c75109fc92db`
- `trussed-core` from the pinned SoloKeys Trussed revision
  `2ea719b28245f0e68960e99aab16131f7f14d8ff`
- `ref-swap` 0.1.2, crates.io package, upstream commit
  `f8a5c15a385e1658947ba74d865b14495e3b37d3`
- `fido-authenticator` 0.4.0-rc.3, upstream commit
  `fae4a1ec8f55d9abe53a7405faf310ef90f3eb71`

The first three crates contain portability changes limited to atomic imports,
dependency declarations, the deprecated `compare_and_swap` shim, and one
explicit lifetime required by the current compiler lint. The local
`fido-authenticator` patch rejects missing or malformed persistent state unless
an explicit provisioning marker authorizes first initialization. It also
propagates state-load failures to CTAP instead of silently using defaults.

All four crates retain their upstream license files. Update the provenance here
if any source is replaced.

The persistent-state patch was written against the dual-licensed upstream
source. It does not copy code, tests, or documentation from Pico FIDO's AGPL
tree or from OpenSK/Wasefire's Apache-2.0 tree.

The 2026-09-06 local PIN/UV patch adds USB token expiry through Trussed uptime,
clears associated authorization state, applies permission/RP/UV lifecycle
checks, and uses `subtle` for secret comparisons. Credential-management HMAC
failure no longer decrements PIN retries. The storage format is unchanged.
See [PIN-token review and provenance](../docs/development/pin-token-security.md)
for the upstream revision checked, specification references and test scope.
