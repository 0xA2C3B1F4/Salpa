# Dependency security

## Initial audit

On 2026-09-03, `cargo-audit` 0.22.2 checked the locked graph of 278 Rust crate
dependencies against 1,239 RustSec advisories.

The audit found no known security vulnerability. It reported two maintenance
warnings:

- `atomic-polyfill` 1.0.3, RUSTSEC-2023-0089, enters through `heapless` 0.7.17
  and `postcard` 0.7.3 in the pinned Trussed graph.
- `paste` 1.0.15, RUSTSEC-2024-0436, enters through `esp-hal` 1.1.2.

These are not ignored. Updating either path changes upstream platform or FIDO
dependencies and needs the normal compile gates followed by regression tests
on a disposable device. The weekly CI audit will still fail if RustSec reports
an actual vulnerability.

## License inventory

Cargo metadata reports a license expression or license file for every resolved
package. `tinyrlibc` 0.5.1 uses `LICENCES.md` instead of an SPDX expression.
The required notice is summarized in `docs/third-party-notices.md`.

Repeat the advisory and license review before every tagged source release and
before publishing any firmware binary.
