# Release hardening plan

The [S2 hardening design](esp32s2-hardening.md) supersedes the earlier final
Secure Download step. Restricted maintenance is not complete ROM closure.
The reusable plan's final stage is blocked, with no burn operations or automatic
flash-key deletion. Bootloader defaults remain the accepted prototype defaults.

This plan separates source evidence from physical-device evidence. Passing an
earlier gate does not prove a later gate.

## Current protected checkpoint

On 2026-09-05 the second protected S2 passed encrypted boot, storage and
attestation initialization, credential power-cycle persistence, signed USB
update, rollback and encrypted ROM recovery. JTAG is disabled. Full ROM
download remains available. The owner reported OpenAI registration and a
PIN-and-button login afterwards. [Evidence](../evidence/README.md) records the
scope of each result. Production provisioning, final ROM policy, independent
review and physical attack resistance remain open. No profile is release
eligible. Existing account keys are not disposable regression targets.

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
  --artifact "$RISSO_KEY_ARTIFACT" \
  --output "$RISSO_KEY_CANDIDATE_MANIFEST" \
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

Do not run this gate on the enrolled OpenAI key. Use a second device whose
credential storage may be erased.

- [x] Select an external active-low GPIO16 button for protected-build FIDO user
  presence. GPIO16 is not a boot-mode strap on ESP32-S2.
- [x] Prove the GPIO16 path and rejection of the GPIO0 BOOT button on disposable
  hardware. The redacted result is
  [`docs/evidence/non-strapping-up-esp32s2-3001ce9.json`](../evidence/non-strapping-up-esp32s2-3001ce9.json).
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

Historical build and device gates, 2026-09-03 through 2026-09-05:

- [x] Added machine-readable development, build-spike, and blocked protected
  profiles.
- [x] Built an unsigned RSA Secure Boot V2 bootloader with pinned ESP-IDF v6.1.
- [x] Verified test-only external signatures using only the public key on the
  verification host.
- [x] Added a reversible `0xE000` layout, clean-build package, private exact-
  backup mode, unused-device functional rollback, protected-region readback,
  and restore tooling.
- [x] Tested the required partition-table move on disposable hardware without
  changing eFuses.
- [x] Implemented and physically accepted signed A/B selection, first-boot
  confirmation, rollback, success persistence, and wrong-key rejection on a
  disposable ESP32-S2 without eFuse changes. The redacted acceptance record is
  [`docs/evidence/signed-ab-esp32s2-0f5bd51.json`](../evidence/signed-ab-esp32s2-0f5bd51.json).
- [x] Implemented CTAPHID `0x51` signed image transfer, fresh GPIO16 approval,
  inactive-slot erase/write, complete readback hash, ROM RSA-PSS verification,
  activation-last, and rollback regressions. A disposable development device
  passed success, power-cut, wrong-key, persistence, and rollback tests without
  eFuse changes. The later protected hardware path also passed normal update and rollback; see the current checkpoint above.
- [x] Added a release-only ESP32-S2 encrypted-storage backend, encrypted signed
  A/B partition profile, fixed decrypted-read mappings, and linker bounds.
- [x] Added a machine-readable, fail-closed ESP32-S2 eFuse plan and readback
  validator. The plan remains explicitly unapproved and produces no burn
  command.
- [x] Built the initial protected package from clean, exactly pinned ESP-IDF
  sources; independently verified its 15 manifest-bound file hashes,
  signatures, and final-offset encryption round trips; and accepted the
  disposable device's read-only eFuse summary against the pristine profile.
  No flash or eFuse write was performed. The redacted result is
  [`docs/evidence/protected-preflight-esp32s2-fe17f88.json`](../evidence/protected-preflight-esp32s2-fe17f88.json).
- [x] Rebuilt the complete package from the audited update fixes in `0d295e8`
  and independently verified its hashes, signatures, and offset-bound
  ciphertexts with the existing prototype keys. A fresh read-only device check
  matched the completed first eFuse stage. At that preflight checkpoint Secure
  Boot was disabled and the replacement package was not yet installed. See
  [`docs/evidence/protected-preflight-esp32s2-0d295e8.json`](../evidence/protected-preflight-esp32s2-0d295e8.json).
- [x] With explicit device authorization, installed and read back the
  replacement initial ciphertext set, then enabled Secure Boot V2 with the
  matching public digest and planned protections. Full eFuse readback and
  independent ROM security information passed. At this checkpoint the device had not been reset
  into the provisioner. Later protected acceptance is linked above; secure ROM
  lockdown remains disabled. See
  [`docs/evidence/secure-boot-v2-esp32s2-0d295e8.json`](../evidence/secure-boot-v2-esp32s2-0d295e8.json).
- [x] Prepared a same-secure-version protected rollback-failure fixture and
  excluded it from every initial-install and recovery set.
- [x] Prove encrypted application boot, A/B recovery, fresh credential-store
  provisioning, and credential persistence on the authorized second device.
  See [protected acceptance](../evidence/protected-ota-esp32s2-20260905.json).
- [x] Prove USB update success, controlled power interruption, first-boot
  confirmation, wrong-key rejection, and rollback on disposable development
  hardware before changing eFuses. The redacted result is
  [`docs/evidence/usb-signed-update-esp32s2-0121171.json`](../evidence/usb-signed-update-esp32s2-0121171.json).
- [x] Review and explicitly authorize the first flash-encryption and Secure
  Boot V2 eFuse stages for the disposable device.
- [ ] Complete the separate final ROM and anti-downgrade design, its disposable
  hardware tests, offline recovery checks and device-specific approval sheet.
  Restricted download is not complete closure.

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
