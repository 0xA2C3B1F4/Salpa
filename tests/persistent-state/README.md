# Persistent-state fail-closed tests

This host-only crate exercises Salpa's patched `fido-authenticator` state
loader through the CTAPHID dispatch boundary. It checks missing, truncated,
bit-flipped, malformed-marker, and Trussed read-error cases. Rejected requests
must leave the complete littlefs backing image byte-identical.

The only accepted first-use path starts with the exact one-time marker written
by a destructive provisioning image. The first valid CTAP request creates
`persistent-state.cbor` and consumes that marker.

The suite also passes real authenticator responses through the firmware's
shared reply-completion module. Missing or corrupt state must not confirm an
A/B candidate. Initialized GetInfo can confirm only when the transport accepts
its reply; a discarded request cannot. Response buffers are cleared after
each outcome. CI runs this suite alongside the storage-fault tests.

The PIN tests also characterize the known valid-state replay limitation.
For both PIN protocols, restoring an old RAM-only state record restores
attempts after the eight-attempt block. The test uses the real dispatcher and
synthetic PINs. It does not emulate flash encryption or access a physical
device. A passing test records an unresolved limitation, not replay resistance.
See the [threat model](../../docs/development/pin-token-security.md).

Run the locked host suite with:

```sh
./tools/test-persistent-state
```

## Resident replacement and assertion continuation

Resident replacement prepares the new key and complete attestation response
before committing a replacement. The new record is staged at `rk-new`, and
`rk-transaction-new` is atomically renamed to `rk-transaction` to commit.
Before that rename, the old credential remains authoritative. Afterwards,
recovery publishes the staged record, removes the old record and key, then
removes the journal. Recovery runs before CTAP2 dispatch and is idempotent;
unreadable journals fail closed. The credential record and key formats are
unchanged. Interrupted transactions must be recovered by this firmware before
any downgrade to firmware without journal support.

The host test injects a persistent I/O failure before and after each tested
Trussed mutation, including the commit and cleanup operations. It then opens
the filesystem-backed LittleFS image in a fresh platform, recovers, performs a
real assertion, checks that only one credential is offered, and replaces it
again. A separate test replaces a credential at the configured capacity limit
and verifies that a rejected extra credential leaves the existing key usable.
These tests exercise syscall boundaries; they do not substitute for physical
power cuts inside flash programming or establish flash replay resistance.

A fake monotonic clock exercises GetNextAssertion at 29,999, 30,000, 30,001 and
31,000 milliseconds, successful continuation refresh, clock reversal and clock
failure. PIN-authorized continuations are covered for both PIN protocols.
GetInfo is checked with Salpa's production configuration and both alwaysUv
states: U2F must never be advertised by this CBOR-only transport.
