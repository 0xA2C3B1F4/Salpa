# Third-party notices

Salpa depends on and redistributes third-party software. The MIT license at
the repository root applies only to Salpa's own code and documentation.

The pinned dependency revisions are recorded in `Cargo.lock`. Cargo registry
dependencies retain the license declared by each package.

The following patched sources are included under `third_party/`:

- `fido-authenticator` 0.4.0-rc.3, MIT OR Apache-2.0
- `interchange` 0.3.2, MIT OR Apache-2.0
- `trussed-core`, pinned from the SoloKeys Trussed revision, MIT OR Apache-2.0
- `ref-swap` 0.1.2, MIT OR Apache-2.0 OR CC0-1.0

Their license texts remain beside the source. `third_party/README.md` records
the upstream revisions and the local portability changes.

The FIDO protocol implementation comes from pinned SoloKeys and Trussed Git
dependencies. Those projects retain their upstream copyright and license
terms. Review the complete resolved dependency graph before each release.

The USB signed-update design also references Solo2 commit
`45311f0b6761187d409ea3e7ea34f896810eb156`, whose admin application and CLI
are licensed `Apache-2.0 OR MIT`. Salpa uses the compatible MIT option for
the vendor-command, user-presence, version, hash, and progress design ideas.
No Solo2 Nordic or LPC55 flashing source is copied or redistributed.

`tinyrlibc` 0.5.1 declares a package license file instead of an SPDX expression.
Its package includes the Blue Oak Model License 1.0.0 and a University of
California redistribution notice. Preserve that file when distributing the
crate or a binary that requires its notices.


The ESP32-S2 PMS integration uses register definitions and behavior documented
in Espressif ESP-IDF revision `fff9895c82d744c7237be8847347bdd1b07c6643`.
The referenced `memprot_ll.h`, `memprot_peri_ll.h`, `memprot_defs.h`,
`sensitive_reg.h` and `memprot.c` retain Espressif's Apache-2.0 notices.
No copy of those source files is included in this change. The Rust policy and
linker integration are local work; the [memory-protection guide](design/esp32s2-memory-protection.md#source-basis-and-provenance)
records the exact upstream references and implementation scope.

The protected S2 linker entry follows `esp-hal` 1.1.2 `linkall.x` and
`esp32s2.x`, using that package's MIT licensing option. It retains upstream
section includes and replaces the SRAM alias reservation for the PMS boundary.
