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

Persistent-state serialization and write failures return a CTAP error and
latch that authenticator instance closed until reboot. The tests fail writes
before and after their storage commit for PIN setup, change, retry decrement
and retry reset in both PIN protocols. Previously issued tokens cannot approve
later requests, including after the backend becomes writable again. A fresh
platform must use the actual committed state, without retrying or restoring
the failed RAM mutation. Maximum-sized RP-ID policy lists exercise serialization
failure without a write. Credential error cleanup and invalid exclude/allow
IDs also check that a failed lazy key-state save cannot be swallowed.

Reset removes `rk-new`, `rk-transaction-new` and `rk-transaction` in addition
to `rk/`. Reset regressions fail orphan cleanup and internal/volatile key
deletion before and after commit, then require a new reset in a fresh virtual
runtime. They check that resident credentials and PIN state are cleared while
the synthetic special-ID attestation key and certificate remain byte-identical.
No device identity is loaded or changed by these tests.

A fake monotonic clock exercises GetNextAssertion at 29,999, 30,000, 30,001 and
31,000 milliseconds, successful continuation refresh, clock reversal and clock
failure. PIN-authorized continuations are covered for both PIN protocols.
GetInfo is checked with Salpa's production configuration and both alwaysUv
states: U2F must never be advertised by this CBOR-only transport.

CredentialManagement tests authenticate synthetic requests with both PIN
protocols and fail directory-start, directory-next and credential-file reads.
Read errors return `Other`, discard enumeration cursors, and permit a new
enumeration after I/O is restored. Empty stores, unknown credential IDs and
an update with the wrong user ID retain their previous CTAP status. These
targeted read tests restore I/O before the next dispatch; they do not establish
that every PIN or crypto operation tolerates a globally unavailable backend.

Successful credential deletion and user updates clear RP, credential and
GetNextAssertion continuations while retaining the healthy PIN grant. Faults
before and after record removal, private-key deletion and user-record writes
must return an error and latch the instance closed. Fresh virtual platforms
open the actual LittleFS image, check committed records, exercise unaffected
credentials and verify the synthetic attestation key and certificate remain
byte-identical. Record removal precedes private-key deletion, so an interrupted
deletion can leave an unreferenced key file. A failed deletion does not promise
complete revocation or automatic cleanup.

Trussed can report a filesystem key-removal failure as
`Ok(Delete { success: false })`. Credential deletion and rotation expect their
old key to exist, so this reply must also return `Other` and latch the runtime.
Tests inject that false reply both before and after the actual key deletion,
then reopen storage and check the private-key presence or saved key reference.
Idempotent reset and resident-replacement recovery still tolerate an already
removed key.

KEK and KWK tests cover both credential-ID versions, lazy creation and explicit
rotation, with errors before and after generation, state writes and old-key
deletion. Cached getters and further rotations reject a latched instance.
After reopening the image, tests use real encryption to check the committed
key reference, verify the other key kind is preserved, rotate successfully,
and perform a nonresident credential creation and assertion. Generation or
cleanup failures may leave unreferenced key files; the test does not claim
that the multi-operation rotation is transactional.
