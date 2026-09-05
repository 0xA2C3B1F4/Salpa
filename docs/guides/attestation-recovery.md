# Preserve the original FIDO attestation identity

The FIDO P-256 attestation key and certificate are separate from the RSA
firmware-signing key and AES-XTS flash key. Retaining those two keys does not
recover the FIDO identity.

The normal runtime calls `verify_development_attestation` before entering USB
polling. It requires the serialized original key at `/fido/sec/00` and the
certificate at `/fido/x5c/00`. The protected `provision-storage` image only
formats littlefs and writes storage initialization markers. It cannot install
either attestation file. Its two-pulse result therefore proves storage
initialization only.

## Recovery contract

Keep attestation keys, certificates and recovery references as durable private
assets. A certificate fingerprint can authenticate a recovered certificate,
but cannot reconstruct its private key. Backup preparation and an independent
restore test must precede any erase that could remove the device's identity.

An existing device must recover the same pair. Creating another identity is a
separate provisioning decision for an explicitly selected device. Never
silently replace it to make a cleared device boot.

The protected S2 [import acceptance](../evidence/attestation-import-esp32s2-20260905.json)
records backup restoration, physically approved import, complete readback and
credential tests. The later [update and recovery acceptance](../evidence/protected-ota-esp32s2-20260905.json)
records the same credential surviving signed updates, rollback and encrypted
ROM recovery. These are scoped prototype results, not a substitute for testing
your own recovery material.

The key inventory and recovery locations remain private. Do not add identity
material, device identifiers or private storage references to this source tree.
Firmware-signing, flash-encryption and attestation custody stay separate.

## Validate a recovered pair

Obtain the original files from a trusted backup. Keep the raw private key in
an owner-only directory, owned by the current user with mode 0600. Use the
independently retained original reference, not a new manifest supplied with
an untrusted replacement pair. With Python and `cryptography` installed:

```sh
python3 -B tools/check-attestation-backup.py \
  --key "$RECOVERED_ATTESTATION_KEY_PATH" \
  --certificate "$RECOVERED_ATTESTATION_CERTIFICATE_PATH" \
  --reference "$ORIGINAL_ATTESTATION_REFERENCE_PATH"
```

These arguments contain file paths only. The checker requires the original
certificate fingerprint, checks the P-256 key/certificate match, AAGUID and
certificate self-signature, and rejects unsafe key files. It prints a result
without key bytes, certificate contents or fingerprints. It does not generate
keys, write restored plaintext copies, authenticate to Keychain or access a
device. Core dumps are disabled before validation. Python and its crypto library may retain memory copies; the checker
does not promise complete memory zeroization.

A passing result verifies the backup pair only. A separate protected import
path must restore those exact files through Trussed into encrypted storage,
with fresh physical presence, before normal-runtime acceptance. The existing
`provision-development` image is not that path: it formats storage, embeds the
key in a build and uses the earlier GPIO0 workflow. Do not run it as a shortcut.
Do not format an existing credential store or create a fallback identity to
make the device boot.

If the original key cannot be recovered, obtain an explicit owner decision
before changing the development attestation identity. That decision does not
authorize changing firmware roots, flash keys or eFuses.

## Protected identity import

`import-attestation` is a separate signed application selected by the
`attestation-import` feature. Building it requires
`RISSO_KEY_ATTESTATION_IMPORT_ACK=INSTALL_ATTESTATION` and the protected encrypted
partition profile. The normal authenticator binary rejects this feature. The
import image cannot be combined with storage formatting, physical fault tests
or USB signed-update features.

The application includes only the selected certificate SHA-256 and its
uncompressed public key, supplied through
`RISSO_KEY_ATTESTATION_CERT_SHA256_FILE` and `RISSO_KEY_ATTESTATION_PUBLIC_FILE`.
It contains no private attestation key. The
[macOS helper](../../tools/macos-key-helper/README.md) imports the durable original
files into local Keychain, creates a separately encrypted backup and tests its
restoration before producing an encrypted staging sector entirely in memory.

Before staging, identify the authorized device, compare eFuses, preserve a full
encrypted FIDO-store snapshot and verify that boot metadata and the first
`ota_1` sector are erased. This prototype flow uses `ota_0` for the signed import
image and `0x200000` for the 4096-byte encrypted staging record. It is not an
import path for a device actively using `ota_1`.

After a fresh five-second GPIO16 hold, the application reads the staging record
through the encrypted DROM mapping, validates its framing, certificate hash and
AAGUID, then mounts the existing FIDO store. It accepts only the exact fresh
storage-initialization tree. Any existing keys, credentials or unexpected files
cause rejection without formatting. Trussed imports the staged scalar into RAM
first, derives its public key and compares it to the expected key before
installing the persistent attestation pair. It verifies both installed records,
erases the staging sector and zeroizes the staging buffer before reporting.

| Repeating pulses | Result |
| --- | --- |
| 1 | Fresh presence not confirmed before the timeout |
| 2 | Attestation installed and verified; staging erase returned successfully |
| 3 | Encrypted mapping or read failed |
| 4 | Staging format, certificate binding or AAGUID rejected |
| 5 | Existing storage mount or version rejected |
| 6 | Store is not the fresh initialization tree; existing identity not replaced |
| 7 | Trussed key validation or expected public-key comparison failed |
| 8 | Persistent installation failed |
| 9 | Installed attestation verification failed |
| 10 | Staging erase failed after installation |

Return to ROM after the two-pulse result. Independently verify raw staging bytes
are erased, read back the encrypted store, recheck eFuses and install the
previously verified normal runtime while preserving storage and boot metadata.
Normal USB enumeration, FIDO attestation verification and credential persistence
are still separate acceptance tests. If import fails after writing any state,
stop and inspect; the next boot must not silently format or replace partial data.
