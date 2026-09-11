# Roadmap

The current milestone is an experimental source release with reproducible
host/build checks and accurately scoped S2 hardware evidence. The
[implementation plan](implementation-plan.md) defines scope and acceptance.

## Complete the current prototype evidence

- Repeat protected browser authentication after disconnecting and reconnecting
  USB, recording browser/OS versions and the observed flow without secrets.
- Complete physical ESP32-S3 transport, credential, persistence, and browser
  acceptance. S2 results do not establish S3 support at those levels.
- Add controlled power-fault tests at the electrical program/erase boundary.
- Extend the tested application epoch-floor and USB ROM-closure evidence to
  the remaining UART and physical-attack boundaries. Treat old bootloader
  replay and encrypted FIDO-state replay as distinct unresolved threats.

## Improve maintainability

Shared host helpers keep file hashes, containment comparisons, Git calls and
SDK-config parsing consistent. Device identity, manifest types, protected
regions and write approval stay in their specific commands.

The next firmware refactor separates board/mode initialization from the normal
S2 request loop. A later macOS helper refactor separates Keychain permissions,
authentication, backup formats, attestation validation and CLI dispatch. Both
need their own regressions, including physical device tests or actual Keychain
approval checks. Do not combine them with a trust-root or backup-format change.

## Evaluate stronger physical protection

Compare a separate secure element with a secure MCU after defining the target
attacker capabilities. Evaluate non-exportable credential keys, P-256 support,
credential capacity, PIN/retry and counter protection, host-to-chip command
authorization, provisioning, update policy, recovery, and available independent
evaluation. Keep FIDO semantics in the upstream stack and integrate through
the appropriate Trussed backend.

A secure element does not automatically protect an authorization decision
made by compromised MCU firmware. The complete design must be assessed.
No chip selection, certification level, or delivery date is promised here.

## Production decisions

Production would require controlled identity provisioning, assigned USB
identifiers, custody and revocation procedures, ROM-policy qualification for
each supported board and maintenance route,
independent security review, and a support commitment. Evaluate whether FIDO
certification is appropriate before making product claims. The experimental
source release does not depend on declaring these future stages complete.

The [S2 hardening design](plans/esp32s2-hardening.md) records the ROM-closure,
anti-downgrade, shared-eFuse and storage-freshness dependencies. The
[final S2 USB hardening stage](testing/esp32s2-final-hardening.md) passed on one
device; that result does not qualify other hardware or physical attack paths.

The latest alpha RustSec scan found no known vulnerabilities in the locked
Cargo graph and reported two maintenance notices, `atomic-polyfill` and
`paste`. Track their upstream replacement paths and repeat the locked-graph
audit for each release. See the [testing guide](testing/README.md) for the
CI run and its scope. This scan does not audit Python packages or certify the
application.
