# Installing and updating Salpa

Salpa currently provides separate command-line tools. There is no unified
installer, guided setup application or graphical installation flow. Host build
checks need no board; protected device provisioning requires a reviewed plan
for the exact board and separate approval of each irreversible stage.

Do not use Salpa as an account's only login or recovery method. Set up an
independent alternative and test it with Salpa unplugged before relying on
the key or carrying out maintenance. A locked or failed device may require
registering a replacement security key with each service. Preserved device
backups do not guarantee credential transfer to another device.

## Choose the right process

| Situation | Process |
| --- | --- |
| Explore or compile the source | Follow [getting started](../getting-started.md); compile fixtures are not installable releases |
| Set up a new protected ESP32-S2 | Follow the staged preparation and acceptance sequence below |
| Update an already working Salpa | Obtain the publisher's signed application and use the USB update procedure below; no private firmware keys or macOS key helper needed |
| Run an unencrypted A/B development test | Use the dedicated [development procedure](../development/signed-ab-update.md) on a disposable board |
| Recover a device that will not start | Use its previously verified recovery plan and preserved identity; normal USB OTA requires a running application |

There is no pre-provisioned firmware download in the current source release.
People provisioning their own device build and package source for their own
board, keys and security profile. A user who receives a compatible, already
signed update from their device's firmware publisher follows the update steps
below without building or signing it. The S3 port is not yet accepted as a
complete physical authenticator.

## New protected S2: prepare before writing

1. Identify the board, chip revision, flash size and current security state.
   Confirm native USB and the GPIO16-to-GND presence button. Use a separate test
   board for provisioning experiments. Never erase an enrolled account key to
   simplify a test.
2. Prepare maintainer custody before producing install images. The RSA firmware
   signing root, per-device AES-XTS flash key and FIDO attestation pair have
   different purposes. Preserve every existing identity. On a genuinely new
   device, establish and back up its intended development identity explicitly.
   The current macOS helper requires a local code-signing identity and stores
   keys in local Keychain records with interactive authentication. It supports
   one custodian and one flash-key record, not a device fleet.
3. Create a private key inventory and test encrypted backups by restoring and
   comparing them. Keep backup passwords separate. Transfer required backups
   to separate offline media and test that copy. A connected staging disk is
   not offline storage. Keep originals until custody, integration and recovery
   checks are complete. Follow [firmware signing and maintainer key management](key-management.md) and
   [attestation preservation](attestation-recovery.md).
4. Install the pinned build dependencies, then prepare the bootloader,
   provisioning and application build manifests for the selected profile.
   `tools/build-signed-ab-bootloader.py --protected-external` and
   `tools/build-protected-app.py` are build tools. Review the
   [protected build inputs](../development/esp32s2-efuse-plan.md), including
   their explicit compilation acknowledgements.
5. Run `tools/prepare-protected-package.py` with the build manifests, signing
   public key and installed key helper. It signs and verifies images, creates
   offset-specific ciphertext, checks encryption round trips and writes a
   package manifest outside Git. macOS prompts for key use. This tool does not
   write the board. Its deliberate rollback-failure image is for testing and
   is excluded from normal install and recovery sets.

## New protected S2: install and accept in stages

The [eFuse template](../development/esp32s2-efuse-plan.md) records the sequence
of flash-encryption setup, ciphertext installation/readback, Secure Boot
setup and protected acceptance. It remains unapproved and does not issue burn
commands. A protected bootloader may change eFuses when booted on an unsecured
board, so even its first boot belongs to the device-specific procedure.

After the exact plan is reviewed and separately authorized:

1. Execute only the approved stage on the identified board, with stable power.
   Verify all written regions and security state before the next stage.
2. Initialize the encrypted credential store through its separate physically
   gated provisioning image. Storage initialization does not install FIDO
   attestation. Install the intended recoverable attestation pair through the
   separate [attestation import procedure](attestation-recovery.md).
3. Install the matching normal runtime and validate FIDO enumeration, credential
   creation and assertion, then persistence across power loss. Preserve the
   expected identity and compare complete write readbacks.
4. Establish valid boot metadata for the known-good runtime. The
   [fresh encrypted metadata procedure](usb-signed-update.md#fresh-encrypted-boot-metadata)
   is only for verified raw-erased metadata on a fresh device. Never use it to
   replace an existing device's OTA history.
5. Accept signed USB installation, first-boot confirmation and recovery while
   checking that the same credentials survive. Final ROM restrictions are a
   separate [hardening decision](../plans/esp32s2-hardening.md).

`tools/signed-ab-device.py install` is for the unencrypted signed A/B
**development-test profile**. It is not an installer for the protected profile.
Do not substitute it for the staged protected procedure.

## Protected runtime: signed USB update

These steps require an installed protected S2 runtime with signed USB update
support and GPIO16 presence. A GPIO0 development build without the updater
cannot use this procedure. Match the existing partition and presence profile
when rebuilding a development device. An application update alone does not
enable Secure Boot, flash encryption or irreversible eFuse protections.

These are user installation steps. You do not need private firmware keys or
the macOS key helper. The firmware publisher signs the update before you
receive it; a builder managing their own root first follows the separate
[maintainer signing procedure](key-management.md#maintainer-sign-a-firmware-update).

1. Obtain the normal signed application from your device's firmware publisher.
   Check that it is intended for the device's profile, existing trusted root
   and allowed security version. Do not generate or import a signing key to
   install it.
2. Select the ordinary signed plaintext application, named
   `runtime-usb-signed.bin` in a protected package. Do not select an
   offset-encrypted flash image, provisioner or rollback-failure fixture.
3. With the host dependencies installed, inspect the image without USB access:

   ```sh
   python3 tools/salpa-usb-ota.py \
     "$SALPA_ASSIGNED_USB_VID" "$SALPA_ASSIGNED_USB_PID" \
     "$SALPA_SIGNED_UPDATE_IMAGE" --dry-run
   ```

   This checks image structure and describes its version and hash. Signature
   and trust-root verification belong to package preparation and device acceptance.
4. Connect the working device in normal FIDO mode. Run the same command without
   `--dry-run`. Press GPIO16 only when prompted for fresh physical approval.
   The device installs the inactive slot, verifies it and activates it last.
   Keep power connected until installation completes.
5. Reset or reconnect as directed, perform a successful FIDO operation to confirm
   the candidate, then verify an existing credential. If confirmation fails,
   the bootloader can return to the previous valid slot on reset. Record the
   result before considering a later update or any hardening change.

The USB tool transfers an already signed image and never needs private
firmware keys. The publisher's macOS authentication during signing and the
user's physical update approval are separate checks. Detailed protocol behavior,
build examples and recovery limits are in [signed USB updates](usb-signed-update.md).

Ordinary FIDO login needs no Salpa companion application. A future macOS
maintenance UI would not make a device with no bootable updater recoverable
after ROM closure. See the [recovery-authorization decision](../design/recovery-authorization.md)
for the distinction between firmware repair and restoring old FIDO state.
