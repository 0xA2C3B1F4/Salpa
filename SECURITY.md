# Security policy

## Supported scope

Salpa is experimental source, without production security support or FIDO
certification. Security fixes are delivered as reviewed source updates. Keep an independent way to access important accounts.

The protected ESP32-S2 has passed hardware Secure Boot V2, flash encryption,
GPIO16 presence, credential persistence, signed USB updates, rollback and ROM
recovery. The earlier unencrypted development profile remains available for
bring-up. Full ROM download at the accepted checkpoint, physical attack
resistance, production provisioning and independent review remain open.
See the [security model](docs/design/security-model.md) and
[ESP32-S2 test results](docs/testing/esp32s2-results.md).

## Report a vulnerability privately

Use GitHub
[private vulnerability reporting](https://github.com/0xA2C3B1F4/Salpa/security/advisories/new)
when the repository provides the **Security > Report a vulnerability** form.
Its availability depends on repository visibility and maintainer settings.
If the form is unavailable, open an issue requesting a private contact route
without describing the vulnerability. Wait for that route before sharing
reproduction details. Do not post an unpatched vulnerability in a public issue.

Include the affected source commit, hardware profile, build features, and a
minimal reproduction. Do not attach PINs, private keys, credential databases,
account identifiers, device-specific firmware, or sensitive raw USB captures.
Share sanitized evidence first and agree on handling any necessary private data.

There is no promised response-time or production-support SLA for the alpha.
The maintainer will assess reports and coordinate fixes and disclosure.
