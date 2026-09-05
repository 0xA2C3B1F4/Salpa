# Firmware signing and maintainer key management

This guide is for firmware publishers and people building their own device
who manage its signing and recovery keys. Ordinary users do not need private
firmware keys or the macOS key helper to sign in or install an already signed
update. Follow [installing a signed USB update](installing-and-updating.md#working-device-signed-usb-update)
for that workflow; the publisher signs the image before distribution.

## Key roles

| Key or identity | Purpose | Custody |
| --- | --- | --- |
| RSA-3072 firmware signing key | Authorizes firmware accepted by devices trusting its public root | Firmware publisher or builder managing that root |
| Device-specific 32-byte AES-XTS flash key | Prepares offset-encrypted install and recovery images for one device | Maintainer responsible for that device's recovery plan |
| FIDO P-256 attestation key and certificate | Establishes the authenticator's attestation identity | Separate identity provisioning and recovery custody |

These are different from the account credentials used during ordinary FIDO
authentication. The firmware signing key is not needed for a login signature.
The macOS helper's code-signing certificate is also a separate identity: it
identifies the host executable, not the device's trusted firmware root.

For an already provisioned device, import and preserve the existing keys.
Importing them changes neither firmware nor eFuses. Never generate a
replacement key to work around an import or recovery failure.

## Local Keychain records

The helper lives at `~/Library/Application Support/RissoKey/rissokey-key-helper`. Its source is `tools/macos-key-helper/main.swift`. It uses the local file-based `~/Library/Keychains/login.keychain-db`, explicitly selects that Keychain, and sets `kSecAttrSynchronizable=false`. These items do not synchronize through iCloud.

Both generic-password records use service `fi.rissotek.rissokey.local-keys.v1` and separate accounts `signing` and `flash`. Their labels distinguish firmware signing from device flash encryption. They contain the original key bytes. The helper has no plaintext key-export command.

## Authentication and access

Every signing, flash encryption, and backup operation first checks the Keychain ACL, proves that a noninteractive retrieval is denied, and then creates a fresh `LAContext`. `deviceOwnerAuthentication` requires Touch ID or the macOS account password. Authentication reuse is zero, and the context is invalidated after that operation. Cancellation stops the operation before output is written.

The file Keychain separately controls access to the secret. Every application list, including the owner ACL, is empty. No application receives permanent trust. Choose **Allow**, never **Always Allow**, in the Keychain access dialog. The helper rechecks the ACL after retrieval and refuses to sign if an application was added. The helper itself is signed with an existing local Apple code-signing certificate and uses Hardened Runtime without debugging or library-injection exceptions. This certificate is unrelated to the device's firmware signing key.

The OS adds integrity and partition bookkeeping ACLs. On the tested macOS 26 installation, the stored password-selector bit is returned byte-swapped. The helper accepts only that observed representation or the documented representation. Fresh owner authentication and the actual noninteractive-denial test are independently required; the implementation does not rely on this selector alone.

Access is scoped to the current macOS user's login Keychain. Another application can request access, but cannot read silently with these ACLs. A user who deliberately authenticates an unrelated application can grant it access. Administrators, a compromised user session, and retained plaintext originals are outside a guarantee of non-exportability. This is a software RSA key, not a Secure Enclave RSA key.

The implementation uses the local file Keychain plus explicit owner authentication; it does not claim Data Protection Keychain or Secure Enclave protection. Relevant Apple references: [Keychain implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), [ACL access](https://developer.apple.com/documentation/security/secaclsetcontents), and [LocalAuthentication](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)).

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

The helper maintains `~/Library/Application Support/RissoKey/key-inventory.json`
as a mode-0600 file in an owner-only directory. It records names, purposes,
device scope, responsible local account, Keychain references, original-copy
references, backup references, status, and restore-test dates. This is the
default inventory path, not a record of a particular maintainer's current
storage. Keep actual locations, backup decisions and pending device work in
private operational documentation. The signing public-key fingerprint is
non-secret; the inventory and backups are never public-export inputs.

The FIDO development-attestation P-256 key and certificate form a separate
identity. The helper exposes a third record named `attestation-v2`; that name
is part of its current compatibility contract. Preserve an existing device's
original pair. A new identity requires an explicit provisioning decision and
must never be a fallback after recovery fails. See
[attestation recovery](attestation-recovery.md) and the
[helper instructions](../../tools/macos-key-helper/README.md).

## Maintainer: sign a firmware update

Build a normal runtime for the intended device profile and trusted signing
root, following [package preparation](installing-and-updating.md#new-protected-s2-prepare-before-writing).
Keep the build, source-provenance, public-key and package checks.
`tools/prepare-protected-package.py` uses Keychain for signing and flash
encryption. Supply `--signing-public-key` and the build manifests;
`--key-helper` may select an installed signed helper, otherwise the standard
path is used. Do not pass private signing or flash-key contents to the command.

The unencrypted development-profile tool `tools/prepare-signed-ab-package.py`
also uses Keychain for the trusted signing key. Its unrelated untrusted key
input exists only for a wrong-key negative-test fixture.

Each image signature and each offset encryption has its own authentication. RSA-PSS signatures use SHA-256 and a 32-byte salt. The adapter pads the frozen image to 4096 bytes and passes only the public key and completed signature to `espsecure sign-data`. Flash AES-XTS stays inside the helper and is roundtrip-checked in memory. The existing USB OTA tool consumes the resulting signed image without needing secret keys.

Provide users with the verified normal signed application
`runtime-usb-signed.bin` and its intended profile/version information. They
install that image with the USB update tool and fresh device-button approval.
They do not run the signing helper, enter the maintainer's macOS credentials,
or receive private keys. Offset-encrypted factory images and deliberate
rollback-failure fixtures are not ordinary USB updates.

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

The flash key has its own Keychain record and retention decision. It is not
included in the signing-key backup. Do not automatically rotate or delete it.
Retain it while the device's recovery plan depends on generating or validating
offset-encrypted images. Ordinary signed USB updates do not require the host
to hold this key; the running device handles encrypted flash writes.

Before changing retention, document and test the recovery path that will
remain, including any dependency on ROM download and retained encrypted
packages. Final ROM restrictions and key deletion are separate decisions;
neither follows automatically from a successful update. Preserve attestation
recovery material independently. See the [hardening plan](../plans/esp32s2-hardening.md)
for these dependencies and the [test reports](../evidence/README.md) for scoped
prototype results. Keep each device's pending actions and actual backup
locations in the private inventory and maintenance notes.

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
