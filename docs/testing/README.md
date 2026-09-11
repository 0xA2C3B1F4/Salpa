# Testing

Salpa keeps automated checks, physical device tests and browser reports
separate. A passing host test or firmware build does not establish that a
device boots, preserves credentials or resists a physical attack.

## Repeatable checks

The [getting started guide](../getting-started.md) contains the commands for
host tests, export checks, firmware builds and strict Clippy checks. These
checks use public fixtures and require no board, account or operational keys.
The native macOS helper tests cover cryptographic compatibility and malformed
backup rejection. They do not test Keychain permissions or authentication
dialogs.

Use [GitHub Actions](https://github.com/0xA2C3B1F4/Salpa/actions) to check the
complete run for the exact commit you intend to use. The firmware validation
artifact records the configured build profiles, their Clippy results and the source
export hashes. Artifacts have a 90-day retention period. Preserve the relevant
results separately when qualifying a release. Compile fixtures are not
installable release packages.

## Device results and limits

The [ESP32-S2 test summary](esp32s2-results.md) records the tested configuration,
dates and methods for protected boot, credentials, signed updates, rollback
and recovery. Its browser section records a manual test without a protocol capture;
the scripted FIDO checks provide separate protocol-level evidence.

Source revision IDs in these records identify retained development history,
which is separate from the public repository's initial snapshot. The signed
image SHA-256 in each image-bound receipt identifies the tested firmware;
restarting public Git history does not extend acceptance to another image.

The [security model](../design/security-model.md) explains the remaining
physical and software trust boundaries. The
[S2 hardening plan](../plans/esp32s2-hardening.md) covers work required before
final ROM restrictions; the [final S2 results](esp32s2-final-hardening.md) record
the completed USB ROM-closure test. ESP32-S3 compilation has passed, but complete physical
S3 acceptance has not been established. There is no FIDO certification or
independent security assessment.

For a new device run, record the source revision, board and security profile,
test method, result and untested cases. Verify credential signatures and
readbacks where the procedure calls for them. Keep device identifiers,
credentials, key-custody records and raw sensitive captures out of public
reports. Review the relevant provisioning or update procedure before touching
hardware.

## Acceptance after firmware changes

Existing hardware results qualify only their recorded sources and profiles.
The [final S2 results](esp32s2-final-hardening.md) record protected GPIO16
authentication after ROM closure. Later firmware changes require checks
appropriate to the change, including fresh action, release,
cancellation, timeout and long-hold maintenance when presence handling changes.

The [persistent-state tests](../../tests/persistent-state/README.md) cover
resident replacement recovery and assertion continuation expiry on the host.
Passing these regressions does not establish physical power-loss acceptance
or qualify every development and protected profile.

### USB update regression coverage

The host tests in `src/usb_update.rs` cover descriptor rollback versus
host-claim mismatch, abort in every uncommitted phase, session-ID wraparound,
rejected writes without progress, full-slot bounds in both A/B orientations,
and activation exactly once. A composed CTAPHID/updater test distinguishes
transport `Cancel` and `INIT` from vendor `Abort`. Existing transport and
presence-gate tests separately cover cancellation while waiting for approval.
Run them with the host-unit-test command in the getting started guide.

These tests use synthetic image/signature fixtures and a simulated flash/RSA
backend. They prove state-machine behavior, not the ESP ROM verifier or real
flash fault behavior. In particular, the composed test supplies presence as a
test input; it does not exercise the board's button or the main polling loop.

Before qualifying firmware with the reordered descriptor check, verify on an
authorized test device that an older descriptor advertised as a current epoch
is rejected with `Rollback`, while an at-or-above-floor descriptor differing
from the host claim is rejected with `VersionMismatch`. Neither may activate.
Also check approval-wait cancellation, explicit abort after approval, fresh
presence for a new session, a valid signed update and existing-credential
authentication. Preserve the previous slot and record the tested source and
profile. Earlier physical acceptance remains scoped to its recorded images.

### USB update lifetime acceptance

The updater's host tests use a controllable backend clock. They cover exact
idle and absolute deadlines, all live phases, successful progress renewal,
non-renewal by status or invalid requests, backwards time and clock wrap,
expiration during backend work and RSA verification, fresh approval afterward,
and terminal activation without repeated writes. The maximum-slot test uses
100 ms of simulated time per backend operation in both A/B orientations.
Simulated time is not a measurement of device performance.

The 120-second idle limit and 15-minute absolute lifetime require physical
qualification of each candidate as appropriate to its changes. The
[current acceptance status](esp32s2-results.md#current-acceptance-status) records
completed tests and remaining limits. On the authorized test device:

- Record the source, signed image hash, board profile and existing credential
  baseline. Keep historical test records tied to their original images.
- Install a valid signed image normally and with deliberate host delays. Record
  erase, transfer, verification and total durations. Include the maximum image
  size intended for the release and the supported host workload.
- Pause separately during erase, receiving and verification beyond the idle
  deadline. Confirm expiry, no activation and a fresh button action to restart.
- Continue slow valid progress until the absolute deadline. Confirm that
  status polling and transport resynchronization cannot extend approval.
- Verify INIT, Cancel and Abort behavior inside the live window, cancellation
  while awaiting presence, and rejection of invalid and older images.
- Repeat failed-candidate fallback, relevant power interruption cases, normal
  FIDO/PIN authentication and the existing credential's signature.
- Verify normal USB operation and the already selected ROM policy without
  changing eFuses or consuming security epochs for the timer change.

Normal-image lifetime tests were recorded on 2026-09-10; maximum-size images
and electrical interruption still need device qualification. Software tests
and compile-only fixtures do not qualify a signed installable image. The
[memory-protection policy](../design/esp32s2-memory-protection.md) is included
in the same candidate and has the additional acceptance gate below.


### RAM permission acceptance

The protected S2 candidate includes both the USB lifetime policy and PMS RAM
permissions. Keep a known working signed image in the other slot during first
acceptance. Record image hashes, build features and the existing credential
baseline; preserve all original identity, key and backup references.

- Verify the linked code/data boundary and handler placement. Read `RKMP` from
  the candidate: all four lock and monitor bits must be set, fault bits clear,
  and every permission field must match that candidate's linked layout.
- Confirm normal enumeration, GetInfo, PIN authentication, fresh GPIO16
  presence and the existing credential's verifiable signature. Confirm storage
  persistence after a cold boot, without clearing or restoring the store.
- Repeat a signed update while PMS is active, including cache-disabled flash
  work and verification. Repeat the USB idle/absolute deadline checks above.
- Test ordinary reset, cold boot, both A/B orientations and failed-candidate
  fallback, including a return to the previously accepted image. Require
  successful reinitialization and unchanged eFuse policy on each normal boot.
- In a separately reviewed, explicitly authorized test image, test prohibited
  code writes through both SRAM aliases and execution from writable SRAM/RTC.
  Use only fixed disposable test locations, no caller-supplied addresses, no
  credential data and no persistent writes. Confirm the fault is detected and
  processing stops, then recover by reset and verify the existing credential.
  Such a test interface must not be present in normal firmware.
- Record actual fault behavior separately from register readback. If any
  permitted operation faults, investigate the exact address class and code
  placement rather than weakening permissions until the test passes.

Normal-image PMS readback and compatibility checks, and five prohibited-access
tests on a separate instrumented image, were recorded on 2026-09-10. Their
scope and remaining limits are in the
[current acceptance status](esp32s2-results.md#current-acceptance-status).
Host register-model tests establish policy encoding, bounds, readback failures,
lock handling and status redaction. They do not emulate the S2 bus fabric.

### USB recovery observation

The [current acceptance status](esp32s2-results.md#current-acceptance-status)
includes an unresolved recovery that required cable reconnection. Start with
the same normal image, host port and cable. Record a baseline, then manual RESET
and USB power cycles separately. Change one condition at a time. Investigate
interrupted-update recovery after this baseline is understood.

`tools/fido2-recovery-observer.py` records one attempt with UTC and monotonic
timestamps. It distinguishes enumeration, HID open, CTAPHID INIT, fragmented
PING, security policy, idle update status, PMS readback and GetInfo. Supply the
expected versions and PMS boundaries from the independently retained build
record. For example, with private paths supplied by the operator:

```sh
python3 -B tools/fido2-recovery-observer.py \
  --identity-reference "$IDENTITY_REFERENCE" --output "$RECOVERY_OUTPUT" \
  --firmware-version 0.1.0 --security-version 5 \
  --iram-end 0x40028000 --data-start 0x3ffb8000
```

Use python-fido2 2.2.1 and an enrolled protected S2 with a configured PIN.
Check the example values against the candidate's build record before use.
The tool requires an exact VID, PID and serial match, but does not log those
values or raw error messages. Each run creates a new private JSONL file outside
the source tree.

For a manual cycle, add `--wait-for-disconnect`. Wait until the record shows
`wait_disconnect` with one matching device before operating the board. The
tool must observe disappearance and then two seconds of stable sampled
enumeration. It cannot identify whether RESET, power removal or another USB
event caused the disappearance. Record the manual action separately.

An unsuccessful attempt stays failed. The tool samples enumeration for six
seconds afterward and does not retry HID or CTAP. A parent-process deadline
bounds native calls that hang; the last `started` event identifies the unfinished
stage. Preserve the record before any separately named retry or cable change.
Sampled enumeration can miss brief bus transitions, and the firmware status
interface does not report the hardware reset cause.

The observer requests no firmware, eFuse or credential writes and does not
operate RESET or power. Success covers transport and status checks only.
Verify the existing credential and manual PIN/GPIO16 authentication separately
before recording complete recovery acceptance.
