# ESP32-S2 hardening before final ROM closure

This is a design for further hardening of the tested ESP32-S2 prototype. It
does not authorize flashing, eFuse writes, key replacement or key deletion.
The reusable eFuse plan remains unapproved, and its final ROM stage has no
burn operations.

## Current hardware evidence (2026-09-06)

The separately authorized counter-only transaction on maintenance version
`0.1.5-epoch-maint` advanced `SECURE_VERSION` from raw `0x0000` to `0x001f`
(floor 0 to 5). Independent ROM capture compared all 95 fields and their
permissions: only that field changed. Eleven counter bits remain. Both normal
and maintenance images matched their encrypted references with VALID sequences
15/16. A cold boot and assertion with the existing credential passed afterward.
The first separate eFuse-reader reconnect timed out; re-entering ROM allowed
the complete comparison. Preserve those failed connection receipts as well.

The subsequent normal image from source `47fb9cd` includes the update-target
mapping guard described below. Signed USB installation into each slot, a
controlled cold boot after each installation, and both existing-credential
assertions passed. Independent ROM comparison matched that image in both slots
with VALID sequences 17/18, selecting ota_1. All 95 eFuse fields and permissions
still matched floor 5, and the current complete encrypted snapshot matched the
device.

A separately authorized trial then placed an original-root-signed epoch-4 image
in ota_0 with the higher VALID sequence 19, leaving the epoch-5 ota_1 at sequence
18. Full write readback passed. A controlled cold boot selected epoch 5, the
existing credential still signed successfully, and a freshly approved USB
BEGIN was rejected with `Flash` before a session was created. Independent ROM
comparison confirmed both images and VALID 19/18 metadata unchanged, with all
95 eFuse fields and permissions still matching. This demonstrates the older
image rejection and the update guard on this device. The normal image and original VALID 17/18 metadata were then restored with
full readback and unchanged eFuses. Normal cold boot and the existing credential
passed afterward. The subsequent final closure and post-closure tests passed
for native USB; see the [final hardening report](../testing/esp32s2-final-hardening.md).
That report also records the lost ROM recovery path, untested physical UART
route and the macOS test-receiver correction.
Earlier starting-point and rehearsal sections below describe their original
stages; they are not the current hardware counter value.

## Tested starting point

The [S2 test results](../testing/esp32s2-results.md) cover Secure Boot V2,
release-mode flash encryption, signed USB installation, failed-candidate
rollback, encrypted ROM recovery and preserved credentials. The protected
runtime tested on 2026-09-05 used security version 3. Full ROM download
remained available. Before any device-specific operation, verify the board's
identity, revision, installed software and complete eFuse state anew.

At that starting point, the installed-package bootloader configuration had
`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` disabled. Salpa's USB update code rejects
an image security version below the running application's value. Its custom
OTA confirmation marks boot metadata valid but does not advance an eFuse
counter. These are useful update checks, without hardware-enforced minimum
firmware age.

## ROM policy and shared eFuses

The source basis is ESP-IDF 6.1 commit
`fff9895c82d744c7237be8847347bdd1b07c6643`, matching the protected build.
The [S2 eFuse table](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/efuse/esp32s2/esp_efuse_table.csv)
and [S2 implementation](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/efuse/esp32s2/esp_efuse_fields.c)
distinguish these settings:

| Field | Meaning in the pinned S2 implementation | Design consequence |
| --- | --- | --- |
| `ENABLE_SECURITY_DOWNLOAD` | Restricted ROM maintenance | Does not completely close ROM download |
| `DIS_DOWNLOAD_MODE` | Disables all download boot modes; this is what `esp_efuse_disable_rom_download_mode()` sets | Candidate for final closure, subject to exact revision review and testing |
| `DIS_USB_DOWNLOAD_MODE` | Disables USB OTG use in UART download boot mode | A transport-specific restriction, not a substitute for all-mode closure |
| `DIS_USB` | Disables the USB peripheral | Incompatible with the intended normal USB FIDO/update service; keep unset |
| `DIS_FORCE_DOWNLOAD` | Disables the forced-download function | Already zero and write-protected in the established baseline; it cannot now be changed independently |
| `SECURE_VERSION` | 16-bit monotonic firmware security field | A finite security-epoch budget, not a version number to increment on every release |

`DIS_DOWNLOAD_MODE`, `DIS_USB_DOWNLOAD_MODE`, `ENABLE_SECURITY_DOWNLOAD`,
`DIS_LEGACY_SPI_BOOT` and `SECURE_VERSION` share `WR_DIS` bit 18. Protecting any
one through that group also freezes the security-version counter. Do not
write-protect this group while future security-floor increases are required.
Disabling download is itself a one-way 0-to-1 change; group protection is a
separate operation. The earlier shared group at bit 2 already locks JTAG,
cache controls, `DIS_USB` and `DIS_FORCE_DOWNLOAD` in the current baseline.

The previous plan's final step only enabled restricted download. It has been
replaced with a blocked design gate so that its name cannot imply complete
closure. Espressif also distinguishes restricted download from full closure in
its [S2 flash-encryption guide](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s2/security/flash-encryption.html#best-practices).
An earlier successful USB-ROM recovery does not establish that transport's
availability in restricted download mode. Test the intended UART/USB route
on a separate board before choosing restricted maintenance as an interim step.

The existing protected bootloader selects secure download in its defaults.
[Secure Boot initialization](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/bootloader_support/src/esp32s2/secure_boot_secure_features.c)
can burn security settings, and the IDF flash-encryption initialization also
changes download policy. The current no_std application does not run IDF's
normal application startup. Review actual call paths and linked configuration;
do not infer first-boot safety from a menu setting. The default builder keeps
the previously tested provisioning configuration. The optional read-only
profile below booted on the test device on 2026-09-06. All 95 eFuse fields and
permissions remained unchanged across installation and subsequent boots.
This establishes first-boot behavior on that provisioned device; the remaining
hardening gates are described in the [test results](../testing/esp32s2-results.md#hardening-trials-on-2026-09-06).

## Read-only bootloader candidate

`tools/build-signed-ab-bootloader.py --protected-external --read-only-efuses`
builds an alternative for an already provisioned ESP32-S2. It enables IDF's
application anti-rollback checks with the full 16-bit `SECURE_VERSION` field.
The signing root and partition layout remain the same. This option does not
flash a device, sign a replacement root or authorize an eFuse change.

Stock IDF can advance the counter when it selects an already valid image or
initializes empty OTA metadata. This candidate replaces
`esp_efuse_update_secure_version` at link time with a function that allows only
an unchanged value. It also replaces the pinned ESP32-S2 eFuse programming
backend, `esp_efuse_utility_burn_chip_opt`, with an error return. The builder
checks the resulting ELF for the read/check functions and both replacements,
and rejects a binary that still contains either original writer or
`efuse_hal_program`. It rejects virtual eFuses and skipped image validation.
The normal Rust application's confirmation still changes only OTA metadata.

The candidate runtime binds confirmation to the actual DROM MMU mapping of
its application descriptor, then checks the version and security epoch.
Matching version text alone was insufficient: a fallback could share the
name of a rejected candidate. The mapping check prevents the fallback from
confirming that other slot, even if the two descriptors are identical. Host
tests cover this case and invalid/non-flash mappings. The new epoch-4 runtime
was installed into `ota_0` through signed USB update and remained selected
after a complete power cycle. The identical normal image then booted in
`ota_1`. ROM comparison of both complete image ciphertexts and encrypted
metadata confirmed separate VALID records for both slots (sequences 3 and 4).
A failed epoch-4 candidate also rolled back without losing the saved credential.
Rejection and confirmation of a failed candidate with identical version text
remain covered by host tests, rather than a separate physical fixture.

These guards prevent bootloader-driven provisioning and counter advancement.
They do not prevent an independently authorized ROM tool or a separately
signed maintenance application from writing eFuses. Before closing ROM access,
the maintenance procedure must specify how future epoch changes are approved,
how both slots are qualified, and how an interrupted change is recovered.
The shared write-protection group must remain writable for that procedure.
Do not treat the read-only candidate as a complete counter-advance mechanism.

The host-tested preparation in `src/platform/security_epoch.rs` binds a
counter-only delta to the device, bootloader, trust root, complete observed
BLOCK0 words and the exact signed-content digests of two qualified slots. It preserves every other bit, including
the shared write lock, and requires exact before/after comparisons. The
installed-image verifier authenticates each complete signed image; the OTA
layout check requires distinct VALID slots and the actual executing mapping.
The separate `epoch-preview` runtime exposes only the image and metadata
checks for device testing. A separate counter-maintenance candidate contains a
programming adapter and explicit request transport. On 2026-09-06 its epoch-5
build passed controlled cold boot, existing-credential use, fixed-plan inspection
and a fresh long-hold/release rehearsal on the device. Both images and distinct
VALID records were checked before and after the gesture; the hardware counter
remained zero. No programming request was sent. The read-only preview still has
no programming path. That rehearsal did not exercise electrical programming;
the subsequent counter and nonzero-floor rejection results are recorded above.

At floor zero, boot tests can establish that the candidate boots and leaves
eFuses unchanged. They cannot prove rejection by a nonzero hardware floor.
Plan a separately approved counter stage while ROM recovery remains available,
test rejection of an older correctly signed image, and only then request the
final ROM-closure approval. Raising the floor must not strand the A/B fallback.

The counter limits applications through the trusted bootloader's checks. It
does not establish that an older bootloader signed by the same retained root
is unbootable. An older signed bootloader without the checks remains a concern
for physical flash replay. ROM closure and encrypted flash reduce ordinary
rewrite access; they do not prove resistance to this physical attack.

## Inspecting policy through normal USB

The candidate runtime exposes a read-only security-status request through
the existing USB transport. `tools/fido2-security-status.py` takes a private
USB identity reference and an output path outside Git. It reports the hardware
counter separately from the application's advertised security version,
the remaining bit budget, ROM policy, USB availability settings, flash
encryption count, protection masks and chip revision. It reads no key blocks,
MAC address, credentials or attestation data, and performs no writes.

The request is vendor command `0x51`, payload `0x11`. Its 32-byte `RKS1`
response contains the raw 16-bit counter at offset 4, its population count at
6, `WR_DIS` at 8, policy flags at 12, flash encryption count at 16, `RD_DIS`
at 17, revoked-root mask at 18, chip major/minor revision at 19/20 and the
application security version at 24. Integers are little-endian; unused bytes
are zero. Policy flag bits 0–5 represent `SECURE_BOOT_EN`, `DIS_DOWNLOAD_MODE`,
`DIS_USB_DOWNLOAD_MODE`, `ENABLE_SECURITY_DOWNLOAD`, `DIS_USB` and
`HARD_DIS_JTAG`, respectively. Unknown layouts and inconsistent counts are
rejected by the host decoder.

This provides a check after an approved ROM closure without reopening ROM.
Compare it with independently captured full eFuse readback while ROM remains
available. A counter-only stage permits another complete ROM comparison.
The pinned espefuse 5.4.0 implementation warns that `DIS_DOWNLOAD_MODE` can
stop communication before ROM readback confirms the change. Do not promise
a complete independent post-closure dump: retain the pre-closure capture,
then check the intended status through normal USB and test ROM denial. A runtime response is not independent proof of
its own integrity, a complete eFuse dump or proof that a ROM connection fails.
Those remain separate physical acceptance checks. On 2026-09-06 the selected
USB fields matched the independent ROM baseline, and a subsequent complete
ROM read confirmed that all 95 eFuse fields and permissions were unchanged.
The reported hardware floor remained zero while the application epoch was four.

The protected S2 builder and package validator limit application security
versions to 0–16. Sixteen eFuse bits represent that many increments, not the
integer range 0–65535. Keep the same security epoch for ordinary releases.
Exhausting the field prevents further hardware-floor increases. These build
limits do not themselves advance or prove a hardware counter.

The CLI field value is the raw bitmap. For example, `SECURE_VERSION=0x000f`
represents security epoch 4; the numeric CLI value 4 would set only one bit.
A host-only espefuse 5.4.0 virtual test confirmed this conversion and that
write-protecting `DIS_USB_DOWNLOAD_MODE` also freezes `SECURE_VERSION` through
shared bit 18. This was an emulated field-operation test, not a physical burn.

## Read-only epoch preview candidate

The protected builder's `--runtime-variant epoch-preview` selects version
`0.1.3-epoch-preview`. Its separate `security-epoch-preview` feature requires
`SALPA_EPOCH_PREVIEW_ACK=READ_EPOCH_ONLY`. It cannot be combined with the
rollback fixtures, provisioning or attestation import. The
normal runtime's feature list excludes it. No eFuse programming code is linked
by this feature; normal FIDO and signed USB updates retain GPIO16 approval.

After the candidate has booted and been confirmed through the normal FIDO
check, `tools/fido2-epoch-preview.py` compares both installed images with private
signed input files. Supply `--identity-reference`, `--expected-slot0`,
`--expected-slot1` and a new `--output` path, all outside the repository.
The tool sends only vendor read requests. It neither confirms a candidate nor
raises the counter. A saved image digest must also be tied to independent boot
and credential tests before it can qualify an epoch-advance plan.

The request is vendor command `0x51`, payload `0x12` followed by slot 0 or 1.
The 64-byte `RKE1` response contains status at byte 4, requested slot at 5,
executing slot at 6, security epoch at 8, signed image size at 12, the signed
content's SHA-256 at 16 and both VALID metadata sequences at 48 and 52.
Integers are little-endian; other bytes are zero. Status 0 means the image's
signature and metadata checks passed; 1–4 mean busy, invalid layout, invalid
image or invalid request. The updater must be idle, and metadata plus the
executing mapping must agree before and after verification. Error replies
clear all image data. The host rejects inconsistent fields, changed metadata
between slot reads and mismatching expected images.

The candidate at revision `cef9f85` passed a full ESP32-S2 release build and
Clippy with warnings denied. The compiled build script rejected missing
acknowledgement, a wrong target and six incompatible feature combinations.
Known eFuse programming symbols were absent from its ELF. On 2026-09-06,
the signed candidate booted in `ota_0`, passed the FIDO contract and produced
a valid assertion with the existing test credential. Both on-device signature
checks returned the expected signed-content digests and separate VALID records
with sequences 5 and 4. Selected USB security fields remained unchanged.
This proved the read-only preview on that device. Counter programming and
final ROM closure had not yet been tested at that stage; later results are
recorded in the current hardware evidence above. After replacing the preview with
normal images, a complete ROM read confirmed all 95 eFuse fields unchanged.
Both normal images matched in full, with VALID sequences 7 and 6 and slot 0
selected. The latest complete private snapshot incorporates fresh metadata and
credential-store reads; its whole-image checksum matched the device before and
after capture. This is not a full restore test.

## Required order for ESP32-S2 hardening

1. Preserve the exact signing root, flash key, attestation pair and credential
   store. Verify an independently usable account recovery method. Read and bind
   the board revision and all current eFuse permissions to private evidence.
2. Build and test the final bootloader and application policy on a separate,
   explicitly authorized board. Review normal and fallback boot paths,
   provisioning binaries, test features, alternative boot paths and debug
   settings. Retain release-feature checks and fresh GPIO16 presence.
3. Implement hardware anti-downgrade only with a complete confirmation policy.
   Both fallback and candidate must satisfy the proposed floor. Test an older
   correctly signed image, a wrong-key image, failed self-test, torn metadata,
   power loss around confirmation, and exhaustion of the 16-bit field.
   The current custom Rust confirmation does not call the IDF OTA API that
   normally manages the security epoch. A bootloader toggle alone is insufficient.
4. Test signed USB updates and reset recovery with both valid OTA slots under
   the final policy. Confirm the same credentials before and after each test.
   Inspect both slot contents and boot metadata. A previous rollback test may
   have left a failed candidate; do not assume two valid recovery images exist.
5. Complete offline backup transfer and restore checks. Select full ROM closure
   only after accepting that loss of both bootable applications, a damaged
   bootloader, or some interrupted writes may be permanently unrecoverable.
   The current signed USB updater writes application slots only. It provides no
   bootloader replacement path after ROM closure, even with the retained keys.
6. Prepare a device-specific change sheet with current values, proposed field
   changes, exact order, shared protection effects and passed physical evidence.
   Full closure would set `DIS_DOWNLOAD_MODE`, while leaving `DIS_USB` unset
   and preserving future `SECURE_VERSION` writes. Additional fields and their
   locks require their own justification. Request immediate approval from the device operator
   for that concrete sequence, then verify normal boot, USB update and absence
   of ROM access on both applicable transports.

Before step 6, apply the [PIN-state replay decision gate](../development/pin-token-security.md#device-acceptance-before-irreversible-hardening).
The current S2 has no trusted mutable reference that rejects a whole old valid
FIDO-state snapshot. Host testing confirms that restored state replenishes PIN
attempts. Require an explicit decision from the device operator on this remaining physical risk;
if replay-resistant attempts are required, defer closure until a suitable
protected-counter or secure-element design is qualified. A long random PIN
adds guessing resistance but does not establish state freshness. This decision
does not replace the immediate approval for the exact eFuse changes.

Apply the [recovery-authorization decision](../design/recovery-authorization.md)
as well. A macOS companion is not part of the current recovery trust boundary
and cannot restore a missing USB endpoint after ROM closure. Do not add raw
FIDO-state restoration to the signed updater. If independently bootable USB
rescue or mandatory Mac permission becomes a requirement, reopen that design
and its device qualification before closing ROM. Preserve app-free login.

The pinned [IDF OTA description](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/docs/en/api-reference/system/ota.rst)
describes anti-rollback and its finite counter. The minimum security epoch
must advance only after a qualified candidate is accepted and a compatible
fallback exists. A/B recovery and rejection of old vulnerable firmware are
separate requirements. There is no final burn sequence ready for approval yet.

## Persistent state and physical attacks

Complete the [physical-attack applicability gate](../design/physical-attack-applicability.md)
before final ROM approval. The reviewed S2 package exposes documented memory
terminals; embedded flash is not proof of an inaccessible bus. The reference
board schematic and the actual specimen must remain distinct evidence.
AR2022-003 and AR2023-007 identify potential S2 applicability, while the cited
experiments do not demonstrate the complete attack on this S2. Download closure
does not disable normal encrypted SPI boot. Carry these remaining risks into
the device-specific approval sheet without estimating a compromise time.

AES-XTS protects flash confidentiality, and littlefs handles consistency under
interrupted writes. Neither proves that a presented encrypted snapshot is the
newest one. Review rollback of PIN retries, signature counters and credential
state separately. Closing ROM download removes one access path, while an
attacker with physical access to flash may still attempt snapshot replacement.
This attack has not been demonstrated against the tested prototype configuration.

The existing [PIN-state review](../development/pin-token-security.md#threat-model-restoring-old-encrypted-pin-state)
is the canonical assessment of current code, the isolated replay regression,
ROM access boundaries, counter endurance, power-loss handling and recovery.
Keep this limitation separate from the finite firmware security-epoch budget.

Host-side fault models can test atomic state changes and fail-closed behavior.
A MAC can detect unauthorized modifications but cannot by itself detect replay
of an old valid state. Strong rollback resistance needs a trusted monotonic
reference outside the replayable storage. Reusing the finite firmware eFuse
field for PIN attempts or every signature would exhaust it and is unsuitable.
Physical fault injection, side channels and invasive extraction remain
unevaluated; documentation must not claim resistance based on software tests.

## Key custody and a later hardware revision

Keychain authentication controls the helper's use of its records. Retained
plaintext originals remain another access path. An encrypted backup on
connected storage does not establish offline recovery. Follow
[firmware signing and maintainer key management](../guides/key-management.md): copy to separate offline
media, restore and compare there, record the result privately, and only then
seek the separate retention/deletion decision. Keep passwords elsewhere.
Deleting an APFS/SSD file does not prove older snapshots or copies are erased.
Flash-key retention depends on the selected recovery model; attestation
recovery material remains a durable private asset.

For the current S2, prioritize tested boot policy, controlled updates, PIN and
presence handling, fail-closed storage, and recoverable maintainer custody.
For a later board, evaluate a secure element or secure MCU with non-exportable
credential keys, authorized operations, protected retry/counter state and a
reviewed provisioning/recovery design. A chip that blindly signs commands
from a compromised host MCU would leave significant gaps. No component has
been selected, and no physical security or certification level is claimed.

## Additional release gate: PIN/UV lifecycle

The source review on 2026-09-06 confirmed missing PIN-token expiration and
ordinary HMAC/PIN-hash comparisons. These are source findings, not demonstrated
device attacks. Correct and test them before final ROM closure. Preserve all
earlier evidence against its original source revision; it does not qualify
new firmware automatically. Repeat PIN-authenticated credential use, fresh
physical presence, signed updates, rejection and A/B recovery with the corrected
images. Reassess the security epoch and qualify both slots before generating a
new device-specific counter plan. The earlier epoch-4 plan is superseded.

The separate `security-epoch-maintenance` candidate is separate from normal
firmware and the read-only preview. It requires an owner-only plan outside Git
and explicit build acknowledgement. Its inspect and long-hold rehearsal
requests do not program eFuses. Its programming request binds both image digests
and the fixed plan, rechecks qualification after physical approval, and attempts
only a counter delta. The host tool additionally requires a recent, one-use
approval record. This preparation does not authorize a device operation.

## Selected presence input is a closure gate

GPIO16 is the selected protected input. Qualify fresh action, held-at-start
denial, release, cancellation, timeout, power cycles and the separate long-hold
maintenance gesture. The consent state machine changed with the FIDO fixes,
so repeat its device acceptance against the corrected source.

Complete the [PIN/UV correction acceptance](../development/pin-token-security.md)
and the selected-input tests before preparing the immediate eFuse approval
table. Retain the old device evidence and backups under their original hashes.
The subsequent [final USB ROM-policy tests](../testing/esp32s2-final-hardening.md)
passed. Physical UART denial and physical-attack resistance remain untested.

## Current normal-image qualification

The 2026-09-06 epoch-5 GPIO16 round passed the controlled erase, transfer,
verification, activation and confirmation power-cut checks with the existing
credential. Full ROM readback matched both final normal images byte-for-byte,
and all 95 eFuse fields and permissions remained unchanged. However, the final
metadata initially contained sequence 13 as ABORTED for ota_0 and sequence 12
as VALID for ota_1. The device had returned to the working ota_1 image. The
cause of that earlier reset/boot observation remains unresolved, and its evidence
and private snapshot are retained.

Reinstalling the same signed image and observing a controlled USB cold start
passed the FIDO contract and existing-credential check. Independent ROM readback
then confirmed sequence 13 VALID for ota_0 and sequence 12 VALID for ota_1, with
ota_0 selected. Whole-image ROM comparisons matched the same images previously
read fully, and all 95 eFuse fields remained unchanged. A current private
snapshot was also checked against the complete flash contents.

Successful FIDO responses and identical version strings alone do not establish
which slot executed. Require independent VALID metadata for both slots before
irreversible approval; retain any failed attempt separately. The long-hold
maintenance rehearsal subsequently passed on the separate maintenance build.
Independent ROM checks after that rehearsal matched the normal and maintenance
images, confirmed VALID sequences 13/14, and found all 95 eFuse fields and
permissions unchanged. A current complete encrypted flash snapshot matched
the device before and after capture; this is preservation evidence, not a
restore test. At this stage, the device-specific counter-only proposal was
prepared to advance the floor from 0 to 5 while preserving ROM access and
shared write protections. Its approval was separate from final ROM closure.
The subsequent separately authorized counter request returned a failure. A
complete independent ROM comparison found all 95 fields unchanged at floor 0,
with both images and VALID metadata preserved. The cause is undetermined:
the host had discarded the device's status code. The host now retains that
non-secret code. The consumed approval cannot authorize a retry; a new immediate
approval was required. These are historical failed attempts; the separately
authorized final closure is recorded in the current hardware evidence above.
The subsequent [final USB ROM-policy tests](../testing/esp32s2-final-hardening.md)
passed. Physical UART denial and physical-attack resistance remain untested.

## Counter-controller qualification correction

A second independently authorized request returned transaction error 6 after
physical approval. Independent ROM checks again found all 95 eFuse fields
unchanged at floor 0, with both images and VALID records preserved. The exact
transaction substage was not reported by that firmware.

Read-only diagnosis found a controller command value of zero with STATUS state
1. The adapter incorrectly required STATUS state 0, confusing a register reset
value with a usable idle condition. The corrected adapter follows
[Espressif's S2 command check](https://github.com/espressif/esptool/blob/v5.4.0/espefuse/efuse/esp32s2/fields.py):
require the read/program command bits to be clear on two consecutive reads.
The second read accounts for the documented clock issue in that implementation.
This confirms an adapter defect consistent with the failed request; the earlier
response alone does not establish its exact failing instruction.

The corrected maintenance candidate is version `0.1.5-epoch-maint`, still epoch
5. It also reports a non-secret transaction substatus on failure: 1 attempted,
2 clock, 3 busy, 4 timing, 5 refresh, 6 coding, 7 state mismatch, 8 staging,
9 program result. These diagnostics do not authorize retry. The normal image,
credential storage and key policy are unchanged. Qualify this new candidate on
the device under separate installation authority before any new counter request.
Retain the original candidate and both failed-attempt receipts. Software tests
and target builds do not establish successful eFuse programming.

The separately authorized `0.1.5-epoch-maint` qualification subsequently passed
on the same S2. The normal fallback and corrected maintenance image each passed
a controlled cold boot and an assertion with the existing test credential.
The fresh long-hold/release rehearsal and subsequent inspection agreed.
Independent ROM comparisons matched both installed images and VALID sequences
15/16; all 95 eFuse fields and permissions remained unchanged at hardware floor
0. A fresh complete encrypted flash snapshot also matched the device before
and after capture. No programming request has been sent with this corrected
candidate. Its electrical programming path and nonzero-floor enforcement still
require separate approval and physical proof. The final ROM policy remains
untested.

## Update layout after hardware-floor fallback

Preparing the old-image test exposed a source-level availability defect.
The bootloader can skip a higher-sequence, correctly signed image below the
eFuse floor without invalidating its OTA record. Selecting an update target
solely from the largest sequence could then designate the executing fallback
as inactive. This is a source finding, not a demonstrated device attack.

The update backend now binds layout selection and activation to the running
application descriptor's DROM mapping, as the confirmation path already does.
A disagreement rejects BEGIN before any erase or write. Host regression tests
cover both slot directions, swapped metadata records and an approved request
that receives a layout error without mutations. This does not silently repair
or reinterpret the records: a controlled metadata repair is required before
USB updates can resume in that exceptional state.

The corrected normal image completed the normal installation, cold-boot,
existing-credential and independent ROM comparison gates described above. The
old-image ROM test has now demonstrated epoch-4 rejection and denial of USB
BEGIN in the deliberately inconsistent state. The separately authorized
restoration of the normal image and original validated metadata also passed
full readback, normal cold boot and an existing-credential assertion. The ROM
path remained available throughout the test.
This fix does not change FIDO storage, the trust root or the hardware floor. Builds sharing epoch
5 remain eligible at floor 5; the floor is a security-epoch boundary, not a
per-build allowlist. Neither this availability guard nor the counter establishes
freshness of replayed FIDO state.
