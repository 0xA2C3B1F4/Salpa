# Security policy

## Supported scope

RissoKey is experimental source, without production security support or FIDO
certification. Security fixes are delivered as reviewed source updates. Keep an independent way to access important accounts.

The protected ESP32-S2 has passed hardware Secure Boot V2, flash encryption,
GPIO16 presence, credential persistence, signed USB updates, rollback and ROM
recovery. The earlier unencrypted development profile remains available for
bring-up. Full ROM download at the accepted checkpoint, physical attack
resistance, production provisioning and independent review remain open.
See the [security model](../docs/design/security-model.md) and [evidence](../docs/evidence/README.md).

## Report a vulnerability privately

This mirror is currently private for owner review. Authorized collaborators
can report concerns in a private repository issue. Before public release, the
maintainer must enable GitHub private vulnerability reporting. Public users
should then use **Security > Report a vulnerability**. If that form is
unavailable, request a private contact route without vulnerability details.
Do not post an unpatched vulnerability in a public issue.

Include the affected source commit, hardware profile, build features, and a
minimal reproduction. Do not attach PINs, private keys, credential databases,
account identifiers, device-specific firmware, or sensitive raw USB captures.
Share sanitized evidence first and agree on handling any necessary private data.

There is no promised response-time or production-support SLA for the alpha.
The maintainer will assess reports and coordinate fixes and disclosure.
