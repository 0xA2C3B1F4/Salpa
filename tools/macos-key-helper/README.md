# Local macOS key helper

`install.py` builds and signs this helper with an existing macOS code-signing
identity. It does not import keys or access a board. Run `test-crypto.py` with the
pinned Espressif Python to exercise host cryptography with disposable fixtures;
tests never access Keychain or display authentication prompts. Temporary files and
Swift module caches use `$TMPDIR`.

## Development FIDO attestation

The `attestation-v2` account is separate from `signing`, `flash`, and the historical
`attestation` inventory entry. Import never overwrites a different Keychain item.
RSA firmware trust, flash encryption keys, and eFuses are outside these commands.

Generate a new development identity only after explicit authorization, into a
durable owner-only directory outside Git. `generate-dev-attestation.py --quiet
DIRECTORY` suppresses fingerprints on stdout and disables core dumps. Retain the
original files and manifest. Code using the generator's functions directly must
disable core dumps in its own process as well.

Run the installed helper commands separately, in this order:

1. `import-attestation KEY_RAW CERT_DER` validates the 32-byte P-256 scalar against
   the DER certificate using CryptoKit and Security, including a sign/verify
   check and the canonical noncritical development AAGUID extension, then imports
   the canonical bundle under `attestation-v2`. It records
   certificate SHA-256 and uncompressed SEC1 public-key SHA-256 in the private
   inventory. The private input must be owner-only; the DER limit is 1024 bytes.
2. `backup-attestation NEW_BACKUP_FILE` requires fresh macOS authentication and
   creates an encrypted backup after native secure passphrase entry and
   confirmation. Use a new passphrase of at least 20 characters, separate from the
   macOS password, and retain it separately. The backup uses PBKDF2-HMAC-SHA-256
   with 600,000 iterations, a 32-byte random salt, and AES-256-GCM. Its format,
   role, certificate hash and public-key hash are authenticated metadata.
3. `restore-test-attestation BACKUP_FILE` must run in a new helper process. It
   asks for the backup passphrase again, decrypts only in memory, matches the
   imported certificate and public-key references, and verifies P-256 signing.
   The recorded encrypted backup must match exactly. The test creates no restored
   plaintext file or Keychain item.
4. `stage-attestation NEW_CIPHERTEXT_FILE` requires the matching backup and a
   successful separate-process restore test. It freshly authenticates both the
   attestation and existing flash-key reads, validates the identity again, then
   writes exactly 4096 bytes of ESP32-S2 AES-XTS ciphertext for address `0x200000`.
   A decrypt/compare check runs in memory before the output is written. The
   helper records ciphertext provenance in the private inventory and prints no
   identity hashes.

On a replacement Mac, use `restore-attestation BACKUP ORIGINAL_REFERENCE_JSON`.
The reference must be an independently retained generator manifest or reference
JSON containing `certificate_sha256`. If it also contains
`public_key_x963_sha256`, that reference must match too. Do not construct this file
from the backup's own metadata: it supplies the independent identity check.

Recovery validates the reference before asking for the backup passphrase,
decrypts in memory, and checks the certificate/AAGUID and P-256 pair. It requires
macOS user authentication before importing into local Keychain. A different
existing `attestation-v2` item is never replaced. No previous local inventory is
required; the helper registers the imported certificate, public key, encrypted
backup and independent reference in its private inventory. This command leaves
the restore-test status pending. Run `restore-test-attestation BACKUP` in a new
helper process before staging is permitted.

Retain the durable original files, independent manifest/reference, encrypted
backup and separately stored passphrase. Host fixture tests cover the recovery
cryptography; actual replacement-Mac Keychain import still requires verification
in that environment.

Backups, staging outputs and inventory files are mode `0600`. No command writes
plaintext staging material or private keys to a temporary file. Owned mutable
secret buffers are cleared on return; framework objects and temporary copies
remain subject to Swift/framework memory management, and the CLI process exits
after each command. Core dumps are disabled by the production helper.

The staging plaintext contract is:

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `RKATST01` |
| 8 | 4 | Certificate DER length, little endian, 1–1024 |
| 12 | 4 | Zero |
| 16 | 32 | Raw P-256 private scalar, big endian |
| 48 | DER length | Certificate DER |
| Remaining | To 4096 | Zero |

Physical installation, a fresh presence hold, verification of installed
attestation, and staging-sector erasure are separate firmware/device steps.
Ciphertext creation does not establish any of those results. Firmware may embed
the expected certificate hash and uncompressed 65-byte public key; it must never
embed the private scalar. Keep encrypted backups and original material until
their retention is explicitly reconsidered.
