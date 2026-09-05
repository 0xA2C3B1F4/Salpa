# Changelog

## 0.1.0-alpha, source candidate

Candidate for an experimental public source release, currently in private
owner review. The current protected ESP32-S2 prototype
has completed normal FIDO operation with Secure Boot V2, release-mode flash
encryption, dedicated GPIO16 presence, signed USB updates, rollback and ROM
recovery. Credential persistence was checked across these operations. The owner
reported Chrome registration and Safari authentication with OpenAI using PIN
and physical presence. See the [evidence index](evidence/README.md) for
which results were measured and which were owner-reported.

This release adds a complete, hash-bound public export, pinned Python test
dependencies, exported-tree tests, ESP32 linking checks and macOS helper
crypto tests. Shared Python hashing, path-containment, Git and configuration
helpers replace identical code in the build and packaging tools. Device
checks and update behavior are preserved.

The S3 port remains under development. This is not a production-ready or
FIDO Certified authenticator. Full ROM download remains available on the
accepted S2, and physical attack resistance has not been independently tested.
The release contains source and documentation, with no provisioned firmware
or private device material.
