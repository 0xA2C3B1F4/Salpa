# Changelog

## 0.1.0-alpha, source candidate

Candidate for an experimental source-only alpha release. The protected
ESP32-S2 prototype has completed normal FIDO operation with Secure Boot V2,
release-mode flash
encryption, dedicated GPIO16 presence, signed USB updates, rollback and ROM
recovery. Credential persistence was checked across these operations. Manual
browser test results cover Chrome registration and Safari authentication
with OpenAI using PIN and physical presence. See the [ESP32-S2 test results](testing/esp32s2-results.md)
for the distinction between scripted checks and manual browser tests.

The candidate includes a hash-bound source export, hash-locked Python test
dependencies, exported-tree tests, ESP32 build and Clippy checks and macOS
helper crypto tests. See the [testing guide](testing/README.md) for the checks.
Shared Python hashing, path-containment, Git and configuration helpers replace
identical code in the build and packaging tools. Device
checks and update behavior are preserved.

The S3 port remains under development. This is not a production-ready or
FIDO Certified authenticator. The subsequent [S2 hardening round](testing/esp32s2-final-hardening.md)
tested a hardware firmware floor of 5 and closed USB ROM access. Physical
attack resistance has not been independently tested.
The candidate contains source and documentation, with no provisioned firmware
or private device material.

## Security and robustness corrections

Resident credential replacement now uses a recovery journal so an interrupted
write can recover without deleting the existing credential first. Host fault
injection covers failures before and after storage mutations. Recover any
pending journal before downgrading to firmware without journal support.

USB transfer failures abort the active transaction instead of reaching a
panic. GetNextAssertion continuations expire after 30 seconds of inactivity.
The USB runtime no longer advertises U2F because its transport does not
implement CTAPHID MSG. See the [persistent-state tests](../tests/persistent-state/README.md)
for the replacement and assertion regression cases.

The vendored optional-reference container now returns `None` when empty
instead of forming a null reference. Protected-package metadata again records
the 32-byte flash encryption key size. These corrections have focused host
regression tests; they do not extend the scope of earlier physical acceptance.
