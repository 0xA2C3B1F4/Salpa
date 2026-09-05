# Persistent-state fail-closed tests

This host-only crate exercises RissoKey's patched `fido-authenticator` state
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

Run the locked host suite with:

```sh
./tools/test-persistent-state
```
