# ESP32-S2 test results

This summarizes prototype tests from 2026-09-04 through 2026-09-10. The original
protected runtime tested on hardware was version `0.1.0`, security version
3, from revision `ef2001b2c9f11a10ef7fd7be6c03a235ad8c4760`. That revision belongs
to the original development history, which is not included in this source
snapshot. These results do not establish physical acceptance of later source
revisions. Use the [testing guide](README.md) for current automated checks.

Start with the current acceptance table below. Historical sections retain
their original stage-specific conditions, including earlier open ROM access
and lower security epochs. Acceptance applies to the recorded image and test
method; later firmware changes need checks appropriate to their scope.

## Current acceptance status

This table consolidates evidence recorded through 2026-09-10. It does not
represent unrestricted release qualification.

| Evidence | Recorded result | Scope and remaining limits |
| --- | --- | --- |
| Source and ELF checks | PMS layout, SRAM aliases and the normal fault handler passed static checks. | These checks do not execute prohibited accesses on hardware. See the [PMS validation record](../design/esp32s2-memory-protection.md#software-validation-2026-09-09). |
| Host tests and builds | The combined PMS and deadline candidate passed 277 tests, nine target builds and strict Clippy. | Register and flash models do not emulate the S2 bus fabric or electrical interruption. |
| Runtime startup refactor | The [module split](../design/architecture.md#runtime-startup) passed 289 host tests, builds and strict Clippy for all nine standard profiles and five additional startup configurations. Protected ELF checks passed with unchanged PMS boundaries, handler placement and `main` frame allocation; reserved stack space increased from 149,328 to 149,332 bytes. The normal protected S2 image passed the [device checks below](#runtime-startup-refactor-2026-09-10). | Hardware checks cover the normal S2 runtime from `33d18d9`; other startup configurations have build evidence only. Reserved space is not a peak stack measurement. Earlier fault and deadline results retain their original image scope. |
| Normal S2 firmware | `de0c8c8` passed PMS permission and lock readback, idle and absolute update deadlines, a slowed signed update and manual browser authentication requiring PIN and GPIO16. | One USB recovery required cable reconnection and remains unexplained. See the [device results](#ram-protection-and-update-deadlines-2026-09-10). |
| Instrumented S2 test image | Five fixed prohibited-access cases produced the expected LED fault indication and stopped USB processing. RESET restored normal firmware and the original credential remained usable. | The fault handler contained test instrumentation. This is separate from the static checks of the exact normal handler. |
| ROM policy | [Native USB ROM denial](esp32s2-final-hardening.md) passed on 2026-09-06; normal firmware read back the closed ROM policy on 2026-09-10. | Physical UART denial remains untested. The earlier open-ROM recovery procedure no longer applies to this device. |
| Remaining update qualification | Maximum-size images and electrically interrupted flash programming remain untested on hardware. | The 2026-09-10 receiving-phase power cycle occurred after idle expiry, so it does not establish recovery from interruption of a live receiving session. |

## Runtime startup refactor, 2026-09-10

Normal protected S2 firmware from `33d18d9`, version `0.1.0`, security version
5, was signed and installed into `ota_1`. The [evidence receipt](esp32s2-startup-20260910.json)
binds these results to the 425,984-byte signed image with SHA-256
`ea6ef85f75fd39c99feae8e24cdf4c211ec52e3ef0f024fb59a725ee3fc8f5ff`.
After USB power removal and
reconnection, CTAPHID INIT, fragmented PING, GetInfo, security and PMS readback,
and idle update status passed. A fresh GPIO16-approved Begin returned inactive
slot `ota_0`, confirming that `ota_1` was running; the session was aborted before
any erase or write. This distinguishes the new image from the previous image,
which reports the same application version.

The original test credential's assertion signature verified, and manual browser
authentication requiring PIN and GPIO16 passed. The existing signing root,
attestation identity and credential store were retained. No eFuses were changed.
These checks cover startup and normal operation. The full fault and deadline
matrix was not repeated, and full update execution from the new runtime remains
untested; the preceding runtime performed this installation.

## RAM protection and update deadlines, 2026-09-10

Normal S2 firmware `de0c8c8` passed PMS permission and lock readback, the
120-second idle and 900-second absolute update deadlines, and a deliberately
slowed signed update. Five fixed prohibited-access cases passed on a separate
instrumented test image: code writes through both SRAM aliases and execution
from writable SRAM, RTC-fast and RTC-slow memory. Each case produced the
expected LED fault indication, stopped USB processing and recovered to normal
firmware after RESET with the original credential intact. Manual browser
authentication requiring PIN and GPIO16 also passed after the final
normal-image boot.

One USB recovery required reconnecting the cable; its cause remains unresolved.
Follow-up checks on the same normal image passed one manual RESET with USB
connected and one USB power cycle using the same cable and port. Both passed
CTAPHID INIT, fragmented PING, security and PMS readback, idle update status and
GetInfo. The original credential's signature and manual browser authentication
requiring PIN and GPIO16 passed afterward. One further trial interrupted a live
update after the first 64 KiB verification step, before activation. USB returned
without an additional cable reconnection or RESET; the same transport and status
checks and the original credential's signature passed. The earlier recovery
incident did not recur in this trial, but its cause remains unresolved.

A receiving-phase power cycle occurred after the idle deadline. Maximum-size
images and electrically torn flash programming remain untested. The exact
normal fault handler retains separate static checks.

## Protected configuration

The 2026-09-05 tests used a WEMOS S2 Mini with 4 MiB flash, native USB on
GPIO19/20, an active-low GPIO16 button and a GPIO15 LED. The protected profile
used eFuse-enforced Secure Boot V2, release-mode AES-XTS flash encryption,
disabled JTAG, encrypted credential storage and signed A/B updates.

Security checks compared eFuse readback against the intended profile and
cross-checked Secure Boot and flash encryption with ROM security information.
Full ROM download remained available at the accepted checkpoint. The device
did not have a separate secure element.

## Physical results

| Check | Method and observed result |
| --- | --- |
| Normal FIDO operation | USB CTAPHID INIT, fragmented PING and authenticator GetInfo passed. Credential creation checked the expected attestation, and assertion signatures verified. |
| Credential persistence | The same test credential produced a valid assertion after USB power removal and reconnection. |
| Signed USB update | Fresh GPIO16 approval permitted installation into the inactive slot. The device verified and activated the image, then passed FIDO checks and an assertion with the existing credential. A subsequent update accepted the valid active-slot metadata. |
| Failed-candidate rollback | A deliberately failing `0.1.1-ab-fail` fixture booted, then a reset restored normal `0.1.0`. Encrypted metadata matched the aborted candidate and valid prior slot. The original test credential still produced a valid assertion. |
| Encrypted ROM recovery | Installed images matched the recovery package before writing. Complete ciphertext readback matched the rewritten bootloader, partition table and active application. Boot metadata, credential storage, the existing trust root and eFuses stayed unchanged. Normal FIDO operation and the same credential assertion passed afterwards. |

The encrypted storage work also verified a public-pattern round trip and
format/mount markers. It identified an ESP32-S2 mapping defect: the MMU flash
target flag at bit 15 was required for the corrected encrypted access path.
The accepted protected runtime included that correction.

## Hardening trials on 2026-09-06

These trials used the same protected ESP32-S2FNR2 revision 1.0 device, its
existing signing root, flash key, attestation identity and saved test credential.
The read-only eFuse bootloader came from revision
`343e39df8ba719b9fb734ec074172a07ac38953d`; the epoch-4 runtime came from
`c0f5177699c6a30da4cf92e25484a5cf16cce8c9`. These source revisions identify the
tested candidates, not acceptance of later changes.

| Check | Observed result |
| --- | --- |
| Read-only bootloader installation | Complete readback matched all 49,152 written bytes. The partition-table sector, both metadata sectors, both application first sectors and complete FIDO partition were unchanged. |
| Bootloader startup | The existing runtime booted, passed the USB FIDO contract and produced a valid assertion with the same saved credential. |
| Signed epoch-4 USB update | Fresh GPIO16 approval allowed installation into `ota_0`. FIDO and the same credential assertion passed, and the image remained selected after complete USB power removal. |
| USB update rejection | The device rejected an epoch-3 begin request and six malformed requests before flash writes. A full image with one altered RSA signature bit and a recomputed signature-block CRC was rejected without activation. The normal image booted after reset. |
| Failed candidate rollback | A correctly signed epoch-4 failure fixture booted once in `ota_1`. The next reset returned to the normal epoch-4 image, and the original credential assertion passed. |
| Update power removal | USB power was removed after the first 64 KiB erase, after 209,312 of 417,792 bytes transferred, and after the first 64 KiB verification of a fully transferred image. Each restart returned to the normal epoch-4 image with idle update state and a valid original credential assertion. |
| Activation and confirmation power removal | Power removal after completed activation, before the first boot, selected the normal epoch-4 image. A second power removal after confirmation kept it selected instead of the different-version preview fallback. The same saved credential assertion passed after both cycles. |
| Both normal slots | The normal epoch-4 image was subsequently installed and booted in `ota_1`, with the original credential assertion passing. ROM comparison matched both complete image ciphertexts. Exact encrypted metadata comparison established `ota_0` sequence 3 and `ota_1` sequence 4 as VALID, with `ota_1` selected. |
| Read-only epoch preview | Revision `cef9f85`, version `0.1.3-epoch-preview`, booted through a signed USB update into `ota_0`. FIDO and the saved credential assertion passed. The device verified both installed signatures and returned matching signed-content digests, separate VALID sequences 5 and 4, and the executing slot. Selected USB security fields stayed unchanged. The counter remained zero. |
| Complete preserved snapshot | A fresh 4 MiB ciphertext read matched the complete flash digest before and after capture. Exact byte comparisons matched the bootloader, both normal images and VALID metadata. The encrypted credential partition was retained privately. This snapshot was not restored during the trial and does not prove portable credential recovery. |
| eFuse invariance and USB status | Full ROM reads before installation and after the new bootloader/runtime had booted showed all 95 fields and permissions unchanged. The new USB status fields matched the independent ROM baseline. |

The hardware security floor remained **0**, while the new application advertised
security version **4**. The older-update rejection above exercised the running
firmware's checks. It did not prove rejection by a nonzero hardware floor.
The power-removal trials stopped between flash commands; they do not establish
behavior during a torn flash program or erase pulse. A dedicated interruption
during the actual metadata erase/program operation remains untested. Nonzero
hardware-floor enforcement and final ROM closure were still open at this
stage; their later results are recorded in the final hardening report.
The completed activation and
confirmation boundaries were tested with full USB power removal. No eFuses were written in these trials.

Both normal images were subsequently restored and compared in full through
ROM. Their VALID records had sequences 7 and 6, selecting slot 0. The complete
eFuse comparison again found all 95 fields and permissions unchanged. A latest
private 4 MiB snapshot combined the previous full read with fresh metadata and
credential-store reads. Its complete checksum matched ROM before and after
capture. A full restore from this latest snapshot has not been tested.

PIN/UV lifecycle and comparison findings identified later on 2026-09-06 added a
release gate at that stage. The [final hardening results](esp32s2-final-hardening.md)
record the subsequent corrected-image acceptance and ROM closure. These earlier
physical results remain scoped to their recorded source revisions.

## Earlier development tests

Signed A/B tests on 2026-09-04 at revision
`0f5bd51130c49c33d94a2cb95de93e4107653930` verified that a failure fixture booted
once and rolled back, a successful image persisted across reset, and an
untrusted image was rejected. Credential storage remained intact during the
writes.

USB update tests on the same date at revision
`0121171100387e306786488312648e4f3b345420` checked a complete wrong-key image by
readback and observed signature rejection without activation or a change to
the active version. Removing USB power during an incomplete update after the
first 64 KiB inactive-slot erase left the previous runtime bootable. After
reconnection, FIDO GetInfo passed and the update state was idle. A failing
`0.1.1-ab-fail` candidate rolled back on its next boot; a successful
`0.1.2-ab-pass` candidate persisted after reconnection and matched its readback
hash.

Both update test sets used an unencrypted development profile with a
development trust anchor and no eFuse-enforced Secure Boot. The interrupted
update test does not establish protected-profile fault handling or electrical
brownout resistance.

A separate GPIO16 test on 2026-09-04 used an unencrypted development profile
at revision `3001ce964946dae9a9bd86297ddab15277cdae78`. It verified a fresh press
for each operation, rejection of BOOT as presence approval, timeout without
GPIO16 and channel recovery after cancellation. Holding GPIO16 during reset
still booted the application. Those results are scoped to that development
profile.

## Manual browser testing

Manual testing with an online service confirmed security-key enrollment and
subsequent authentication using a PIN and physical button confirmation.

The results were recorded manually, without a CTAP or WebAuthn capture.
Browser versions and service authentication after a fresh USB power cycle
were not recorded.
This test does not establish broad browser or service compatibility.

## Maintainer key helper

Separate host tests on macOS verified local, nonsynchronizing Keychain
records, fresh user authentication, empty trusted-application lists and
denial of noninteractive reads by both the helper and an unrelated executable.
Interactive signing and flash encryption matched the existing public root and
protected package. The helper used Hardened Runtime.

Cryptographic fixture tests independently checked RSA-PSS, six AES-XTS
reference vectors, PBKDF2 and rejection of incorrect passwords or altered
backups. These automated tests do not replace the interactive ACL and user
authentication checks. A fresh-process signing-backup restore in memory passed;
restore from an offline medium and import on a new Mac were outside that test.
See [maintainer key management](../guides/key-management.md) for the procedure
and the limits of software keys in a local Keychain.

## Remaining limits

- The [final USB ROM-policy tests](esp32s2-final-hardening.md) passed on
  2026-09-06. The earlier ROM recovery path is no longer available on that
  closed device. Physical UART denial remains untested.
- The separate epoch-floor trial proved rejection of an older signed
  application. Signed A/B rollback alone does not establish that protection.
  Storage consistency checks do not establish resistance to replay of an
  older encrypted credential snapshot.
- These tests do not prove resistance to fault injection, side channels,
  invasive attacks or every electrical brownout. Firmware build coverage of a
  power-cut test binary is not physical fault-test coverage.
- ESP32-S3 has no complete physical acceptance result. S2 results do not apply
  to every ESP32 board or security configuration.
- The project has no FIDO certification or independent security assessment.

The [security model](../design/security-model.md) describes how Secure Boot and
flash encryption protect the prototype, and why they do not provide isolated
credential execution or a trusted display. Keep an independent account
recovery method.

## Corrected source: software checks on 2026-09-06

The [PIN-token review](../development/pin-token-security.md) documents the
confirmed source findings, 25 FIDO/persistent-state software tests and the
separate encrypted-state replay threat. The corrected GPIO16 firmware has the
stage-specific device results below. The later
[final hardening report](esp32s2-final-hardening.md) records completed native-USB
ROM closure and post-closure checks; these earlier records retain their scope.

## Corrected GPIO16 firmware: partial device checks on 2026-09-06

The protected normal runtime built from revision
`5fc076636b0e4296785a2e2a6b3e27c7240e5d6d`, application version `0.1.0` and
security version 5, was signed with the retained firmware root. The device
accepted its 417,792-byte USB update into inactive `ota_1` after fresh GPIO16
approval. The previous security-version-4 runtime remained in `ota_0`.

The new runtime passed USB FIDO GetInfo and verified an existing test
credential's signature after reset and again after disconnecting and
reconnecting USB power. Each assertion used a separate GPIO16 approval. Six
malformed update requests were rejected without starting an update session.
A BEGIN request for the existing signed security-version-4 image was rejected
by the device with rollback status, bypassing the host's version precheck.
No erase or data transfer followed that request.

These checks do not establish PIN-token expiry on hardware, PIN-authenticated
browser compatibility, or hardware-enforced rollback protection. The firmware security version is 5; no eFuse counter was advanced.
The prior eFuse readback and older failure-recovery tests retain their original
scope. Corrected-image failure recovery and the remaining power-cut and
presence tests were required before final ROM closure. The later qualification
and closure results are recorded in the final hardening report.
