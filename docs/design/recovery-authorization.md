# Recovery authorization and a macOS companion

## Decision

Keep normal FIDO login independent of a Salpa application, Mac, maintainer
key or network service. Installing an already signed compatible update keeps
its existing device-side checks and fresh GPIO16 approval.

A future macOS companion could guide firmware repair using the existing
tools. It would improve workflow and key custody, but it is not a security
boundary by itself. Do not add a mandatory Mac approval protocol or a generic
FIDO-state restore command to the current hardening candidate. Their trust,
key recovery and device recovery paths need separate qualification. No such
application or protocol is implemented by this decision.

This assessment on 2026-09-06 extends the existing
[PIN-state replay analysis](../development/pin-token-security.md) and
[hardening plan](../plans/esp32s2-hardening.md). It does not change the frozen
candidate images or evidence tied to their original hashes.

## Different recovery operations

| Operation | Current protection and availability | Effect of a Mac application |
| --- | --- | --- |
| Repair an application while a valid FIDO runtime can boot | Signed USB update checks the existing root and version, writes the inactive slot and activates after verification with fresh GPIO16 consent | Can guide installation without private firmware keys |
| Restore bootloader or raw flash while ROM download is available | Device-specific approved recovery uses retained keys, exact addresses and readback; ROM does not check a custom Mac ticket | Can authenticate its own operator, but another ROM client bypasses its UI |
| Restore old FIDO state | A complete valid snapshot can restore PIN attempts on the same device; no trusted freshness reference exists | An approved restore is still a replay; permission does not prove the state is current |

Recovering a maintainer key on a Mac is another operation. The existing
[Keychain helper](../guides/key-management.md) controls local key use and
encrypted backups. Its restore test does not restore the FIDO filesystem.

The source boundaries are `src/usb_update.rs`, `src/platform/ota.rs`,
`src/platform/storage.rs` and the vendored authenticator's `src/state.rs`.
The updater accepts sequential writes within the selected inactive application
slot, verifies RSA-PSS and the security version, then updates boot metadata.
It has no general credential-store restore command. Do not widen its write
ranges to make a GUI recovery button work.

Two added host regressions exercise the actual updater dispatcher with a fake
flash backend: `unknown_operations_cannot_add_a_raw_restore_path` rejects all
currently undefined operation bytes both idle and during a transfer, even with
claimed presence; `raw_flash_addresses_and_unapproved_writes_do_not_reach_the_backend`
rejects writes without a session and absolute flash addresses presented as
initial offsets. Existing tests cover inactive-slot confinement, signature
failure, descriptor/version mismatch and interruption boundaries. All 116 root
host tests passed on 2026-09-06. The fake backend does not establish physical
flash isolation or actual RSA execution on the MCU. The already recorded
device signature-rejection test remains separate evidence.

Only tests and documentation changed. The production updater and frozen device
images remain unchanged. These checks do not justify an unrestricted claim
that recovery cannot be exploited: ROM access and physical replay are still
open acceptance and threat-model questions below.

Account recovery must remain independent of all these device recovery paths.
Do not use Salpa as the only login or recovery method. Set up an independent
alternative and test it with Salpa unplugged. A locked or broken device may
require registering a replacement key with each service; retained backups do
not establish that the old credentials can be moved to another device.

## Keychain and Secure Enclave

The existing helper stores the retained RSA signing and flash secrets in
separate non-synchronizing local file-Keychain records. It checks ACLs, denies
silent retrieval and requires fresh macOS user authentication before use.
These are local custody controls. The ESP32 receives a signature or ciphertext,
not proof that Touch ID occurred for this installation. A previously signed
image remains installable without contacting that Mac.

Apple's documented
[SecKey Secure Enclave path](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
creates P-256 keys inside supported hardware and cannot import existing
private keys. The retained RSA firmware root cannot be moved into that path.
Wrapping a software key does not make subsequent software signing enclave
execution. Retained originals and backups remain separate custody paths.

A future dedicated P-256 authorization key could require
[`privateKeyUsage`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage)
and [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence)
on the private-key operation. Require fresh authentication per operation and
test cancellation, locked-session access, reuse and unrelated-client denial.
A preceding `LAContext` success alone must not be the only restriction.
User presence can allow the system's password fallback; it is not necessarily
biometric-only. A device signature does not attest the Mac's UI or key-storage
policy, which a separate trusted enrollment process must establish.

Such a key would be additional, purpose-specific authority. Do not repurpose
the firmware root, flash key, attestation key or account credential. No new
key is generated or enrolled by this work.

## Requirements for a later device-enforced permission

The device must verify permission before accepting a protected write. It cannot
trust the app name, host-only identity checks or a USB approval boolean.

- Preserve the firmware root. Define a trusted enrollment or signed delegation
  that binds the recovery public key to this device and allowed operations.
  A requester-supplied key cannot authorize itself. Protect key replacement,
  revocation and policy records against replay too.
- Generate a fresh device challenge using the checked RNG. Sign a canonical,
  domain-separated message containing protocol version, device, session,
  operation, exact payload hash and size, target regions and firmware policy.
  Keep firmware-signature verification independent: user permission must not
  authorize arbitrary executable code.
- Enforce one outstanding challenge, a bounded device-uptime lifetime and
  single use. Clear it on cancellation, restart or failed validation. Consume
  permission before writing; interrupted recovery requires fresh permission.
  Host clock time is not a trusted freshness reference.
- Retain fresh GPIO16 consent and the separate long hold plus release where
  maintenance requires it. Show the exact device and operation before Mac
  authentication, then sign and verify those same bytes. The prototype has no
  trusted transaction display on the key itself.
- Cover every equivalent write path. Older signed firmware or a bootloader
  that omits the rule may bypass it. Qualify both A/B images and reassess the
  hardware security floor before claiming enforcement. Do not consume a new
  firmware epoch merely to prototype this feature.
- Design lost-Mac recovery before enrollment. A non-exportable key cannot be
  copied to a replacement Mac. A separately enrolled backup authority or
  trusted re-enrollment path needs its own access and revocation rules. Avoid
  universal bypass secrets and silent fallback to exportable keys.

Future tests must reject wrong-device, wrong-payload, wrong-operation, reused,
expired and malformed tickets. Cover concurrent requests, key-policy replay,
authentication cancellation and cuts at every commit boundary. Confirm normal
login with the app absent and the Mac unavailable. These tests have not been
implemented or passed by the current firmware.

## Bypasses and availability after ROM closure

The immutable ROM cannot be extended with this approval check. While a ROM
write route remains available, application-only permission does not control
every restore. Secure download mode can retain flash writes; it is not full
closure. The final policy must verify the applicable USB and UART routes.

After full closure, the current USB updater still requires a bootable normal
application. The bootloader has no independently qualified USB rescue service.
If both applications or the bootloader are unusable, a Mac application cannot
recreate that endpoint. Retained signing and flash keys do not change this.
Do not promise general unbricking after closure. Requiring that capability
would reopen bootloader/recovery design and postpone closure.

Physical flash replay bypasses application authorization too. Accessibility
depends on packaging and has not been demonstrated on this board. Fault
injection, compromised authorized firmware, host compromise and recovered key
copies are separate risks. A protected Mac key does not isolate the FIDO
secrets used inside the ESP32 or make the device's flash monotonic.

## Approved FIDO state can still be old

A fresh challenge can authorize yesterday's snapshot today. A Mac's private
latest-generation ledger can constrain its own approvals, but cannot stop a
flash writer that never consults it. Replaying that ledger's backup also needs
consideration. Keeping login independent of the Mac means the device cannot
rely on the Mac checking every PIN attempt.

The existing host regression already demonstrates restored attempts through
the real FIDO dispatcher. A reliable retry policy needs trusted mutable state
outside the replayable filesystem, atomic attempt accounting and safe recovery.
A Mac ticket or snapshot MAC does not supply these. Requiring Mac access to
unseal runtime secrets after every reboot would violate independent login.

Preserve current keys, credentials, attestation identity and original backups.
Continue existing signed-update and A/B qualification. Before final closure,
record acceptance of both physical-state replay risk and possible loss of
software recovery. This decision authorizes no device writes, key enrollment,
storage restore or eFuse changes.
