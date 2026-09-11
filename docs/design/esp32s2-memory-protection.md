# ESP32-S2 memory protection

The protected S2 runtime now configures the chip's Permission Management
System (PMS) before starting USB or opening FIDO storage. The policy separates
executable SRAM from writable data and locks its permission registers until
CPU reset. The [current acceptance status](../testing/esp32s2-results.md#current-acceptance-status)
covers normal operation and five prohibited transactions on a separately
instrumented test image, with the remaining limits recorded alongside them.
Host tests, linker assertions and a successful build alone do not prove
hardware enforcement.

## Policy and initialization

`src/platform/memory_protection.rs` installs this policy for the normal
`release-flash-encryption` S2 runtime, including its preview and maintenance
variants. It does not claim protection for the S3 or development profiles,
separate provisioning binaries, ROM, or code executed before initialization.

| Region or alias | CPU access after initialization |
| --- | --- |
| SRAM code and vectors, IRAM bus | Read and execute; no write |
| Same physical code through the DRAM alias | Read only |
| Mutable SRAM, stack and heap, DRAM bus | Read and write |
| Same physical data through the IRAM alias | No access or execution |
| RTC fast instruction alias | No access or execution |
| RTC fast data alias | Read and write |
| RTC slow primary AHB alias | Read and write; no execution |
| RTC slow secondary AHB and DPORT aliases | No access |

The first 32 KiB of SRAM uses four coarse permission blocks. The finer split
starts at IRAM address `0x40028000`, corresponding to DRAM `0x3ffb8000`.
`ld/esp32s2-memory-protection.x` derives the boundary from the actual linked
RAM code and reserves any necessary padding before mutable data. Both aliases
must meet at that boundary. Misaligned, mismatched or oversized layouts fail
the build or initialization. Executable RTC sections are rejected at link time.

The small `esp32s2-protected.x` wrapper keeps the section layouts supplied by
pinned `esp-hal` 1.1.2. It replaces the HAL SRAM alias reservation with a PMS-aware reservation
before `.data`, retaining the vendor vector, code, data, RTC and stack sections. Updating the HAL requires reviewing this integration.

Initialization follows HAL startup and memory relocation. It binds the four
illegal-access interrupts, clears stale fault flags, sets permissions, enables
monitoring, reads back every selected field, then locks all four PMS banks and
checks them again. It preserves unrelated peripheral and FIFO permission bits.
If any inherited bank is locked, only a complete, matching, fault-free policy
is accepted; the firmware does not attempt to unlock or relax it. A register
or layout failure stops startup before FIDO or USB processing.

An illegal-access handler resides in IRAM and stops processing without logging
addresses or writing flash. It does not try to continue a damaged request.
Interrupt masking during a bounded flash operation can delay handler delivery;
software tests cannot establish the hardware transaction or fault timing.
The locks reset on CPU restart, as specified by Espressif. They are not eFuses
and this initialization performs no flash, credential-store or eFuse writes.

## Read-only status

Protected firmware accepts the exact one-byte request `0x14` on the existing
CTAPHID vendor update command `0x51`. Extra request bytes are rejected by the
normal command dispatcher. The 64-byte response contains:

| Bytes | Meaning |
| --- | --- |
| 0–3 | `RKMP` magic |
| 4 | Format version 1 |
| 5 | Lock mask: IRAM, DRAM, DPORT, AHB in bits 0–3 |
| 6 | Monitor-enable mask, same order |
| 7 | Latched fault mask, same order |
| 8–11, 12–15 | Linked IRAM boundary and DRAM data start, little endian |
| 16–47 | Eight masked permission registers, in source allowlist order |
| 48–63 | Reserved, zero |

The response exposes only the linked layout, permission settings and flags.
It contains no raw fault addresses, memory contents, keys, PINs or tokens.
Reading status grants no update approval and does not renew an update session.
`tools/memory_protection.py` checks the linked ELF and validates this reply
against the candidate boundaries. Protected runtime builds and CI invoke the
ELF check automatically. A successful readback is evidence of configuration,
not a substitute for
controlled access-enforcement and availability tests.

## Stack guard and limitations

The pinned `xtensa-lx-rt` 0.22.0 and `esp-hal` 1.1.2 startup also installs the
main-stack guard watchpoint. The protected build enables it even when a
debugger is attached. It monitors stores at the guard address; it is not a
canary for every function or a detector for every out-of-bounds access.

PMS provides coarse CPU memory permissions, not a separate credential processor.
It does not stop every memory-corruption bug, reuse of existing executable
code, or an authorized program reading secrets from writable RAM. Interrupt
routing, DMA-capable peripherals, caches and other privileged controls are
not isolated from the firmware by this policy. No claim of protection against
physical fault injection, side channels or invasive access follows from it.

Neither PMS nor the stack guard proves FIDO-state freshness, supplies a secure
PIN retry counter, or changes the flash-encryption and signing-key boundaries.
Device evidence remains valid for its recorded images. Later firmware changes
need the [combined acceptance tests](../testing/README.md#ram-permission-acceptance)
appropriate to their scope. The [current acceptance status](../testing/esp32s2-results.md#current-acceptance-status)
records completed checks and outstanding qualification.

## Software validation (2026-09-09)

The combined candidate passes 145 Rust unit tests, 90 Python tests, 31 FIDO
persistent-state regressions and 11 storage fault-model tests. All nine target
profiles compile and pass strict Clippy. Protected normal, epoch-preview and
epoch-maintenance builds also pass the ELF layout and handler checks.

The protected compile fixture places the boundary at IRAM `0x40028000` and
DRAM `0x3ffb8000`. Its stack reservation is 149,328 bytes, 11,296 bytes below
the preceding USB-lifetime-only fixture. This is reserved capacity, not a
measurement of peak stack use. The linked fault handler contains no calls or
returns and disables interrupts before its local stop loop.

These results use public compile fixtures, not the device's installable image.
No device, operational signing key, stored credential or eFuse was accessed in
this software-validation stage. Hardware acceptance was still open at that
stage. Subsequent device tests and their limits appear in the
[current acceptance status](../testing/esp32s2-results.md#current-acceptance-status).

## Source basis and provenance

The original assessment found no equivalent explicit PMS initialization in the
pinned Rust startup. ESP-IDF's application startup initializes PMS, but linking
an ESP-IDF bootloader does not execute that application startup in a Rust image.

Register definitions, alias ranges, lock-reset behavior and the configuration
sequence were checked against Espressif ESP-IDF revision
`fff9895c82d744c7237be8847347bdd1b07c6643`, also pinned by this project's
bootloader tooling:

- [S2 low-level memory protection](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/hal/esp32s2/include/hal/memprot_ll.h).
- [Peripheral and RTC aliases](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/hal/esp32s2/include/hal/memprot_peri_ll.h).
- [S2 memory ranges](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/soc/esp32s2/include/soc/memprot_defs.h).
- [Register field definitions](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/soc/esp32s2/register/soc/sensitive_reg.h).
- [IDF configuration and interrupt setup](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/esp_hw_support/port/esp32s2/memprot.c).
- [IDF application startup](https://github.com/espressif/esp-idf/blob/fff9895c82d744c7237be8847347bdd1b07c6643/components/esp_system/port/cpu_start.c).

These Espressif sources carry Apache-2.0 notices. Salpa's Rust policy, host
register model, status format and linker integration are local implementation
work; no upstream source file is vendored for this change. See also the
[third-party notices](../third-party-notices.md).
