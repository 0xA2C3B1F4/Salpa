# Local macOS key management

RissoKey uses the existing RSA-3072 firmware signing key and the existing device-specific 32-byte AES-XTS flash key. Importing them changes neither firmware nor eFuses. Never generate a replacement key for an already provisioned device.

The helper lives at `~/Library/Application Support/RissoKey/rissokey-key-helper`. Its source is `tools/macos-key-helper/main.swift`. It uses the local file-based `~/Library/Keychains/login.keychain-db`, explicitly selects that Keychain, and sets `kSecAttrSynchronizable=false`. These items do not synchronize through iCloud.

Both generic-password records use service `fi.rissotek.rissokey.local-keys.v1` and separate accounts `signing` and `flash`. Their labels identify firmware signing and the ESP32-S2 prototype's flash encryption. They contain the original key bytes. The helper has no plaintext key-export command.

## Authentication and access

Every signing, flash encryption, and backup operation first checks the Keychain ACL, proves that a noninteractive retrieval is denied, and then creates a fresh `LAContext`. `deviceOwnerAuthentication` requires Touch ID or the macOS account password. Authentication reuse is zero, and the context is invalidated after that operation. Cancellation stops the operation before output is written.

The file Keychain separately controls access to the secret. Every application list, including the owner ACL, is empty. No application receives permanent trust. Choose **Allow**, never **Always Allow**, in the Keychain access dialog. The helper rechecks the ACL after retrieval and refuses to sign if an application was added. The helper itself is signed with an existing local Apple code-signing certificate and uses Hardened Runtime without debugging or library-injection exceptions. This certificate is unrelated to the device's firmware signing key.

The OS adds integrity and partition bookkeeping ACLs. On the tested macOS 26 installation, the stored password-selector bit is returned byte-swapped. The helper accepts only that observed representation or the documented representation. Fresh owner authentication and the actual noninteractive-denial test are independently required; the implementation does not rely on this selector alone.

Access is scoped to the current macOS user's login Keychain. Another application can request access, but cannot read silently with these ACLs. A user who deliberately authenticates an unrelated application can grant it access. Administrators, a compromised user session, and retained plaintext originals are outside a guarantee of non-exportability. This is a software RSA key, not a Secure Enclave RSA key.

The Data Protection Keychain needs a provisioned app identity on this Mac. The implementation uses the local file Keychain plus explicit owner authentication; it does not claim Data Protection Keychain or Secure Enclave protection. Relevant Apple references: [Keychain implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), [ACL access](https://developer.apple.com/documentation/security/secaclsetcontents), and [LocalAuthentication](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)).

## Install and import existing keys

Use an existing macOS code-signing certificate from `security find-identity -v -p codesigning`. This command lists certificates, not the firmware keys. Build caches use `$TMPDIR`.

```sh
python3 tools/macos-key-helper/install.py --identity "$MACOS_SIGNING_CERTIFICATE_SHA1"
HELPER="$HOME/Library/Application Support/RissoKey/rissokey-key-helper"
"$HELPER" import signing "$EXISTING_SIGNING_PEM_PATH"
"$HELPER" import flash "$EXISTING_DEVICE_FLASH_KEY_PATH"
"$HELPER" status signing
"$HELPER" status flash
```

Variables above contain paths or a public certificate identifier, never secret key contents. Imports refuse replacement of a different existing key. Repeating an import of the identical key requires authentication and comparison in memory. Original files remain in place.

The private inventory is `~/Library/Application Support/RissoKey/key-inventory.json`, in an owner-only directory with mode 0600. It records names, purposes, device scope, responsible local account, Keychain references, original-copy references, backup references, status, and restore-test dates. The signing public-key fingerprint is non-secret. The inventory and backups are never public-export inputs.

The FIDO development-attestation P-256 key is a separate identity from both
keys handled here. The original pair is currently unavailable and was not
imported by this helper. Its missing-copy status is tracked in the private
inventory. Do not replace it as part of firmware-signing or flash-key work;
see [attestation recovery](attestation-recovery.md).

The owner subsequently authorized a new development identity for the second
ESP32-S2. The helper stores it in a third account, `attestation-v2`, retaining
the missing original's inventory entry. Its backup, restore test and encrypted
device-staging commands are described in the
[helper instructions](../../tools/macos-key-helper/README.md). This account uses
the same local Keychain and fresh authentication policy; it does not change
the firmware-signing or flash key.

## Sign the next update

Keep the existing build, source-provenance, public-key, and package checks. `tools/prepare-protected-package.py` now uses Keychain for both production keys. Remove the former `--signing-private-key` and `--flash-encryption-key` arguments. Supply the existing `--signing-public-key` and the build manifests as before. `--key-helper` may select an installed signed helper; otherwise the standard path is used.

`tools/prepare-signed-ab-package.py` similarly uses Keychain for the trusted signing key. It still accepts an unrelated untrusted key only to create the wrong-key negative-test fixture. It no longer accepts `--trusted-private-key`.

Each image signature and each offset encryption has its own authentication. RSA-PSS signatures use SHA-256 and a 32-byte salt. The adapter pads the frozen image to 4096 bytes and passes only the public key and completed signature to `espsecure sign-data`. Flash AES-XTS stays inside the helper and is roundtrip-checked in memory. The existing USB OTA tool consumes the resulting signed image without needing secret keys.

Temporary adapter files contain firmware bytes and public signatures only, under `$TMPDIR`; they are removed after use. Secret inputs stay in process memory. Swift and Security may make internal memory copies, so the code does not promise comprehensive memory zeroization. Core dumps are disabled in the helper.

## Encrypted backup and recovery test

Use a separate passphrase of at least 20 characters, stored apart from the backup. The helper asks for it in local secure text fields and never reads it from arguments, environment variables, standard input, or a file. Do not send it through an agent or paste it into a shell command.

```sh
"$HELPER" backup "$OFFLINE_BACKUP_PATH"
"$HELPER" restore-test "$OFFLINE_BACKUP_PATH"
```

The envelope uses PBKDF2-HMAC-SHA256 with 600,000 iterations, a random 32-byte salt, and AES-256-GCM with a random nonce. The role and public-key fingerprint are authenticated. The second command runs in a fresh process, asks for the passphrase again, restores only in memory, checks the existing imported public fingerprint, and signs and verifies a fresh random test challenge. No plaintext restored key is written.

For recovery on a new Mac, install the signed helper and use `restore BACKUP EXPECTED_PUBLIC_PKCS1_SHA256`. Obtain the expected SHA-256 from the independently retained private inventory or derive it from the trusted public key; do not take it only from the backup being restored. This command decrypts in memory, checks the expected root, requires macOS owner authentication, and imports into the local Keychain. It refuses to replace a different existing key. Run an interactive signing test afterwards. Restore does not generate any key.

A connected external-disk staging file is **not yet an offline backup**. Copy the encrypted file and this recovery documentation to a dedicated removable medium, verify its checksum, run the restore test against that copy, then disconnect and store it. Record that medium's location reference privately. The passphrase must remain separate. Keep the original key files until the integration and the required offline restore evidence are complete.

## Flash key retention

The flash key has its own Keychain record and retention decision. Do not automatically copy it into the signing-key backup, rotate it, or delete it. On 2026-09-05 the second test device passed protected boot, storage and attestation initialization, credential power-cycle persistence, signed USB update, automatic rollback and encrypted ROM recovery. The same credential still signed after recovery, and all eFuse values and permissions remained unchanged. See the [physical evidence](../evidence/protected-ota-esp32s2-20260905.json). Full ROM download has not been locked down. Keep the original flash key and local Keychain record for that recovery path. Any later key deletion follows the device/recovery plan and a separate explicit final-ROM-lockdown decision. The owner deferred moving the encrypted backups from the connected external-disk staging location to offline media; do not label that transfer complete or remove originals.

This workflow grants no flash or eFuse authorization.

## Tests

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py'
"$ESPTOOL_PYTHON" tools/macos-key-helper/test-crypto.py
```

The native crypto tests use disposable test material. They compare AES-XTS at aligned and unaligned data-unit addresses with pinned espsecure, verify PBKDF2 against Python, reject wrong passwords and altered backups, and independently verify Swift RSA-PSS with the Espressif salt length. Interactive production-key tests must additionally prove a signed image against the existing public root and compare ciphertext against the existing protected package. Host tests do not prove any device gate.

`tools/macos-key-helper/verify-integration.py` repeats the interactive package comparison. Run it with the pinned Espressif Python and an existing signed image, its trusted public key, and the exact packaged flash plaintext/ciphertext pair. An IDF-generated partition table can differ from the espflash-generated table, even when both describe the same layout; use the package's exact generating tool.

## Current helper scope

The helper currently serves one custodian, one firmware signing root, one
retained device flash-key record, and the documented development attestation
identity. It is not a fleet key manager. Do not reuse the flash record for
another device or overwrite an existing identity. Multi-device support needs
explicit per-device identifiers, inventory changes and a reviewed migration
procedure that preserves all existing records.
