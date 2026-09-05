# Development attestation material

This directory intentionally contains no key material. The repository ignores
every other path below `dev-pki` as a last-resort guard, but generated private
keys should live in a protected directory outside the repository.

Use `tools/generate-dev-attestation.py` to create a development-only P-256 key
and self-signed attestation certificate. The raw key and any provisioning build
that embeds it are secrets. They are not production attestation material and
must never be committed or shared.
