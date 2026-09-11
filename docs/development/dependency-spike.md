# Dependency and target spike

## Baseline result

Date: 2026-09-02

The minimal Rust `no_std` application compiles and links for ESP32-S3. No device was flashed or accessed.

| Item | Tested value |
| --- | --- |
| Host | macOS, Apple arm64 |
| rustup | 1.29.1 |
| Host Rust | 1.97.0 |
| Espressif Rust | 1.97.0.0, `rustc 1.97.0-nightly`, commit `8ea53bcd7` |
| LLVM | 21.1.3 |
| GCC linker | `xtensa-esp-elf` 15.2.0 |
| Target | `xtensa-esp32s3-none-elf` |
| Generator | `esp-generate` 1.3.0 |
| esp-hal | 1.1.2 |
| esp-bootloader-esp-idf | 0.5.0 |
| esp-backtrace | 0.19.0 |
| esp-println | 0.17.0 |
| usb-device | 0.3.2 |
| usbd-hid | 0.10.1 |

`cargo check --locked` passed. `cargo build --locked` produced a statically linked 32-bit little-endian Tensilica Xtensa ELF.

Minimal baseline artifact SHA-256:

```text
33ebcd74cbf58c94e396d4e04261d0694b544b3e4d9a30f22a53653c6755b2c4
```

The artifact is reproducible build output and remains outside the repository under the task scratch directory.

## Observed warnings and limits

- The debug link emits a warning that the ELF has a load segment with read, write, and execute permissions. This is recorded for later linker-layout review. It does not block the dependency spike.
- `cargo check --all-targets` fails because it tries to build Rust's standard `test` crate for `xtensa-esp32s3-none-elf`. The custom target does not provide that crate. Firmware checks use the ESP target. Pure unit tests will use an explicit host target.
- The baseline proves only toolchain and HAL linkage. It provides no USB, CTAP, storage, RNG, credential, or device evidence.

## Tool provenance

Downloaded release binaries were checked against the digests published in their release metadata:

```text
rustup-init:
ec1b9233e7f72990ecd8e62063fa7f6c3dfc2bec8e97f88bff165f9100ac696a

espup 0.17.1:
ab0e937d659396ed2b3b0c0f74d29bdf570217f096ea88fa58b8966cf4d32cba

esp-generate 1.3.0:
fcc8476803ebf17e59845627ea35a33d46150119f03a6e433c44ac981911d5a7
```

## FIDO dependency result

The pinned FIDO dependency gate originally passed without an upstream source
patch. Salpa now vendors that exact dual-licensed revision and applies one
security patch: persistent-state read or CBOR failure reaches the CTAP caller
instead of silently selecting default state. The application compiles a
project-owned `fido_authenticator::Config` with these semantics:

- CTAPHID application dispatch enabled; its aggregate upstream feature also
  compiles a dormant APDU adapter, but no APDU or CCID transport is exposed
- credential ID format V2
- eight resident credentials
- ClientPIN retained by the upstream authenticator
- large blobs disabled
- NFC and CCID transport advertisement disabled
- normal user presence retained

Exact upstream revisions:

| Crate | Revision or version | ESP32-S3 result |
| --- | --- | --- |
| `fido-authenticator` | upstream `fae4a1ec8f55d9abe53a7405faf310ef90f3eb71`, vendored locally | Compiles with the fail-closed persistent-state patch |
| `ctap-types` | `3a5bcecb5286630f38dcc3c65a8f500f7abf2d42` | Compiles unchanged |
| `trussed` and `trussed-core` | `2ea719b28245f0e68960e99aab16131f7f14d8ff` | Compile unchanged |
| `ctaphid-dispatch` | 0.4.0 | Compiles unchanged |
| `trussed-staging` | 0.5.0 with only `fs-info` and `hkdf` | Compiles unchanged |
| `littlefs2` | 0.8.1 | Compiles unchanged after build-environment fix |

The first `littlefs2-sys` build failed because bindgen could not find the Xtensa
GCC `stdint.h`. `tools/cargo-esp` now obtains the active compiler's include and
sysroot paths and exports the target-specific bindgen, C compiler, and archiver
variables. Instantiating littlefs later also required Xtensa `-mlongcalls` and
the upstream no-std C stubs (`littlefs2/c-stubs` and
`littlefs2-sys/tinyrlibc`). That littlefs fix did not need a fork. The later
persistent-state security fix uses the vendored `fido-authenticator` source
described above.

`trussed-staging` has a default `chunked` feature. The manifest disables default features so large-blob support and `trussed-chunked` stay out of this build.

The final dependency-spike build produced this artifact:

```text
SHA-256: b492fb1b0b1a8408465e3f015bf5bb325cf9e8a338d312e7072d2254cc3eb7e6
text:     63,538 bytes
data:      2,012 bytes
bss:     405,284 bytes
```

Most FIDO code was not reachable from the spike entry point and the linker can remove it. These figures prove successful target linkage, not final firmware size or RAM use.

The USB boundary passes for the same target and toolchain. It uses `esp-hal`
native USB OTG plus `usb-device` and `usbd-hid`; see `usb-bringup.md` for the
subsequent authorized Viewe board flash, boot, and readback evidence. No
production USB VID/PID is assigned. At that checkpoint, native USB enumeration had not been attempted through
the board's separate `USB` connector. The [USB bring-up record](usb-bringup.md)
describes subsequent connector testing; see the
[S2 test summary](../testing/esp32s2-results.md) for the working S2 prototype.

## ESP32-S2 transport compatibility

Date: 2026-09-03

The same HAL and HID transport compile and link unchanged for
`xtensa-esp32s2-none-elf` when selected with
`mcu-esp32s2,usb-bringup`. Release Clippy passes with warnings denied. The
resulting transport-only ELF has SHA-256
`f41ed9564fc5c1d661ddf35d03325d08b8b5108d129804d96a9c2588e67fde7b`.

The pinned FIDO graph originally failed on the S2 target because `delog`,
`interchange`, `ref-swap`, and `trussed-core` called read-modify-write atomic
operations that Rust core does not expose for this target.

The application now selects project-vendored copies of `interchange` 0.3.2,
`ref-swap` 0.1.2, and the pinned `trussed-core` 0.2.2. Their atomic types come
from `portable-atomic`; `delog` uses its existing `portable-atomic` feature.
The libraries request CAS support but do not select an unsafe implementation.
`esp-hal` selects `unsafe-assume-single-core` only with its ESP32-S2 feature,
which matches this single-core chip.

Host validation passed 12 `interchange` unit and documentation tests, two
`ref-swap` documentation tests, and three `trussed-core` unit tests. Release
Clippy with warnings denied and full ELF linking pass for both the S2 FIDO graph
and the default S3 graph. This closes the target compilation gate. It does not
prove credentials on the device. The later S2 compile gate does connect Trussed
runtime services; see `platform-services.md` for the stricter evidence boundary.
