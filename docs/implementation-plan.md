# Implementation plan

Salpa aims to provide a small USB FIDO2 authenticator with protected local
credentials, explicit user presence, signed firmware updates and a documented
recovery model. The working prototype is ESP32-S2; ESP32-S3 is a port target.

## Product scope

The current scope is USB CTAP2, ES256 credentials, PIN verification, discoverable
credentials, credential management, persistent storage and physical approval.
OpenAI is one interoperability target. The authenticator must remain usable by
other standards-compatible relying parties, without account-specific protocol
logic or a custom cloud service.

NFC, BLE, Wi-Fi, OTP, PIV, OpenPGP, smart-card emulation and wallet functions are
outside this milestone. Production manufacturing and FIDO certification are
separate future decisions.

SoloKeys and Trussed retain responsibility for FIDO semantics and credential
cryptography. Salpa owns board support, USB transport, flash integration,
randomness wiring, button/LED behavior, provisioning and build tools. Keep
upstream patches narrow and tied to a demonstrated portability or correctness
issue. See the [architecture](design/architecture.md).

## Acceptance checkpoints

| Area | Acceptance requirement | Current scope |
| --- | --- | --- |
| Dependencies | Locked `no_std` graph and linked firmware | S2 and S3 compile checks pass |
| USB | FIDO HID descriptors, reconnects and bidirectional 64-byte reports | S2 physically tested |
| CTAPHID | Framing, INIT, fragmented PING, CBOR, cancellation and timeouts | Host regressions and S2 tests |
| Credentials | Fresh presence, ES256 creation and verified assertion | S2 physically tested |
| Persistent state | Same credential after power cycles; failures never silently initialize a new store | Protected S2 and host fault tests |
| PIN and discoverable credentials | Advertised capabilities work through the upstream stack | S2 development tests; protected browser PIN and presence tested manually |
| Protected maintenance | Secure Boot, encrypted flash, signed USB update, confirmation and rollback preserve credentials | Protected S2 physically tested |
| Browser use | Enrollment and later login with the same key | Protected S2 enrollment and login tested manually with an online service |

The [test results](testing/esp32s2-results.md) records the source revision, hardware
profile and test method behind each result. An S2 result does not establish S3
hardware support, and a host test does not establish a physical security claim.

## Next implementation steps

1. Keep the source candidate buildable from an exported checkout. Run host,
   policy, ESP32 and macOS fixture checks without operational keys. Qualify
   each source release with results tied to its exact revision.
2. Finish the protected browser checkpoint by repeating login after a USB power
   cycle, recording browser and OS versions. Keep account and credential data
   outside shared evidence.
3. Complete S3 physical enumeration, credential operations, persistence and
   browser acceptance using an identified test board.
4. Refactor the S2 board/mode initialization and request loop only with the
   corresponding presence, cancellation, persistence and update regressions.
   Split macOS helper responsibilities with independent Keychain and backup
   compatibility tests. Keep existing key records and formats intact.
5. Complete the [S2 hardening design](plans/esp32s2-hardening.md) before final ROM
   closure. It covers both OTA slots, hardware security epochs, shared eFuse
   protection and recovery. Perform destructive fault tests on a separate board.
6. Evaluate secure-element or secure-MCU hardware against defined physical
   threats, protected counters and command authorization. See the [roadmap](roadmap.md).

Each change should have a bounded purpose and evidence for the behavior it
alters. A toolchain update, filesystem change or build result does not authorize
flashing or irreversible device settings. Enrolled keys retain their identity,
credentials and recovery assets throughout maintenance.
