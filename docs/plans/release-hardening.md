# Release hardening plan

The [S2 hardening design](esp32s2-hardening.md) supersedes the earlier final
Secure Download step. Restricted maintenance is not complete ROM closure.
The reusable plan's final stage is blocked, with no burn operations or automatic
flash-key deletion. Bootloader defaults remain the accepted prototype defaults.

This plan separates source evidence from physical-device evidence. Passing an
earlier gate does not prove a later gate.

## Tested prototype scope

The protected ESP32-S2 tests cover encrypted boot, storage and attestation
initialization, credential power-cycle persistence, signed USB update,
rollback and encrypted ROM recovery. JTAG was disabled and full ROM download
remained available. The [S2 test results](../testing/esp32s2-results.md) separate
host checks, development-device tests, protected-device tests and reported
service interoperability.

The subsequent [final S2 hardening trial](../testing/esp32s2-final-hardening.md)
tested application epoch floor 5 and native-USB ROM denial, followed by FIDO,
PIN authentication, signed updates and fallback. ROM recovery is no longer
available on that device. Physical UART denial remains untested.

Production provisioning, independent review and physical attack resistance
remain open. This functional hardening result does not qualify a production
firmware release. Existing account keys are not disposable regression targets.

## 1. Public source gate

- Publish only the allowlisted tree produced by `scripts/export_public.py`.
- Require a clean development commit and verify every exported SHA-256 digest.
- Run formatting, host tests, dependency review, and secret checks in CI.
- Publish source only for `0.1.0-alpha`. Do not publish firmware binaries.

## 2. Release build gate

- Keep firmware diagnostics out of the normal release feature set.
- Strip debug information and keep integer overflow checks enabled.
- Reject placeholder USB identities and empty serial numbers at build time.
- Record the toolchain, locked dependency graph, build command, artifact hash,
  and source commit for every candidate image.

Build candidates only from a clean commit with a target directory outside the
repository. Then create the private artifact manifest with:

```sh
python3 scripts/record_release_candidate.py \
  --artifact "$SALPA_ARTIFACT" \
  --output "$SALPA_CANDIDATE_MANIFEST" \
  --mcu esp32s2 \
  --features mcu-esp32s2,ctaphid-bringup,fido-stack \
  --security-profile wemos-s2-mini-development
```

The manifest records hashes of the source inputs, tool versions, safe build
arguments, and artifact. It deliberately records only the names of USB identity
environment variables. Keep their per-device values in the protected
provisioning record, never in a public manifest or Git.

The selected profile is validated against `policy/security-profiles.json` and
bound into the manifest by hash. Profile selection is policy evidence, not
proof that hardware protections are active. No current profile is release
eligible.

## 3. Disposable hardware gate

Do not run this gate on an enrolled account key. Use a disposable device whose
credential storage may be erased after its attestation recovery material has
been verified.

- [x] Select an external active-low GPIO16 button for protected-build FIDO user
  presence. GPIO16 is not a boot-mode strap on ESP32-S2.
- [x] Prove the GPIO16 path and rejection of the GPIO0 BOOT button on disposable
  hardware. See the [S2 test results](../testing/esp32s2-results.md).
- [x] Repeat enumeration, CTAPHID, cancellation, LED, PIN, resident credential,
  reset, disconnect, and persistence tests.
- [x] Add controlled power interruption after a partial credential-store program
  sequence and after sector erase but before littlefs operation completion.
- [x] Confirm that both tested interruptions return to a defined state without
  formatting the store.

The physical test did not remove power while the flash controller was still
executing a program or erase command. That electrical brownout case requires a
controlled power switch or glitch fixture and remains open.

Host-only persistent-state hardening completed on 2026-09-04:

- [x] Replaced the pinned Git dependency with a vendored copy of the same
  MIT OR Apache-2.0 revision and preserved both upstream license texts.
- [x] Made missing, malformed, and unreadable `persistent-state.cbor` fail
  closed through the CTAPHID dispatch boundary.
- [x] Limited first state creation to a one-time marker written only by the
  destructive provisioning images.
- [x] Verified missing, truncated, bit-flipped, and malformed-marker cases at
  the CTAPHID boundary. Every rejected CTAP request left the complete littlefs
  backing image byte-identical.
- [x] Simulated both metadata and state-file read errors at the loader boundary;
  both return an error and leave the in-memory state uninitialized.

Run this gate with `./tools/test-persistent-state`. This is host evidence. It
does not authorize an eFuse operation or prove electrical fault resistance.

## 4. Per-device identity gate

- Assign an authorized USB VID and PID.
- Provision a unique non-secret USB serial without placing it in source or CI
  logs.
- Generate attestation keys in a controlled provisioning system.
- Keep production attestation private keys outside both Git repositories.
- Record key custody, device association, revocation, and destruction rules.
- Do not reuse the development provisioner for production. Its firmware image
  embeds the attestation key, and reflashing a shorter normal image does not
  prove that every old app-partition byte was erased.

## 5. Boot and flash protection gate

Use a disposable device and the documentation for the exact ESP chip revision
and tool versions. Do not copy eFuse commands from an old checklist.

- Sign and verify the boot chain before enabling irreversible enforcement.
- Enable flash encryption only after encrypted boot, update, recovery, and
  credential persistence have passed on disposable hardware.
- Disable debug and unwanted ROM download paths only after recovery has a
  tested, signed path.
- Capture eFuse plans before writing and read back the resulting state.
- Do not use an enrolled account key for provisioning or destructive experiments.
  A later final-hardening change needs its own exact device authorization.

Implemented and tested capabilities:

- Machine-readable security profiles, a fail-closed eFuse-plan validator, and
  package manifests bind target configuration, build inputs and file hashes.
  Plan validation emits no burn command.
- The Secure Boot V2 package workflow verifies executable signatures and
  final-offset encryption round trips before installation. Deliberate
  rollback-failure fixtures are excluded from initial-install and recovery sets.
- Development-device tests cover reversible partition migration, signed A/B
  selection, wrong-key rejection, controlled update interruption, first-boot
  confirmation, persistence and rollback.
- Protected-device tests cover Secure Boot V2, encrypted storage, signed USB
  updates, rollback and encrypted ROM recovery with preserved credentials.

See the [S2 test results](../testing/esp32s2-results.md) for the scope of each
hardware result. Final ROM and hardware anti-downgrade policy still require a
complete design, disposable-device tests, offline recovery verification and a
device-specific approval sheet. Restricted download is not complete closure.

See `docs/development/secure-boot-v2.md`, `docs/development/signed-ab-update.md`,
`docs/guides/usb-signed-update.md`, and `docs/development/flash-encryption-storage.md`, plus
`docs/development/esp32s2-efuse-plan.md`, for build evidence and the boundary between host
compatibility and physical-device acceptance.

## 6. Release acceptance gate

- Commission an independent security review of the platform boundary and
  provisioning flow.
- Resolve every high-severity finding or document why release remains blocked.
- Repeat browser interoperability on supported operating systems.
- Decide whether FIDO certification is required before making product claims.
- Publish signed source provenance and release notes only after every required
  gate has evidence.

Every physical action needs a disposable target and its own evidence. A passed
source or host-build gate never authorizes eFuse programming.
