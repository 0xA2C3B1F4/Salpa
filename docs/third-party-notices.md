# Third-party notices

RissoKey depends on and redistributes third-party software. The MIT license at
the repository root applies only to RissoKey's own code and documentation.

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
are licensed `Apache-2.0 OR MIT`. RissoKey uses the compatible MIT option for
the vendor-command, user-presence, version, hash, and progress design ideas.
No Solo2 Nordic or LPC55 flashing source is copied or redistributed.

`tinyrlibc` 0.5.1 declares a package license file instead of an SPDX expression.
Its package includes the Blue Oak Model License 1.0.0 and a University of
California redistribution notice. Preserve that file when distributing the
crate or a binary that requires its notices.
