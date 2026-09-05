# Non-strapping user presence

The WEMOS S2 Mini's built-in BOOT button pulls GPIO0 low. ESP32-S2 samples
GPIO0 during reset and enters its serial downloader when the pin is low. A FIDO
confirmation button must not double as that boot-mode control in a protected
device.

The protected build uses an external active-low button on GPIO16. On the
official WEMOS pinout, GPIO16 is the right-hand outer pin immediately above a
GND pin. Connect a normally open momentary button between GPIO16 and that GND.
The firmware enables the internal pull-up, so it needs no external pull-up for
this device test.

Sources:

- [WEMOS S2 Mini board page and pinout](https://www.wemos.cc/en/latest/s2/s2_mini.html)
- [Espressif ESP32-S2 boot-mode selection](https://docs.espressif.com/projects/esptool/en/latest/esp32s2/advanced-topics/boot-mode-selection.html)

## Build separation

`non-strapping-user-presence` changes the normal FIDO application's button from
GPIO0 to GPIO16. Development builds keep GPIO0 unless they select this feature.
The `release-flash-encryption` feature selects it automatically, which prevents
an encrypted protected build from silently retaining the strap pin.

Provisioning and physical storage-fault images still use the built-in BOOT
button for their explicit five-second maintenance gesture. Those images are
forbidden by every protected and release profile. Their use does not define the
normal authenticator's confirmation input.

The reversible device-test profile is
`wemos-s2-mini-non-strapping-up-test`. Build its signed A/B application variants
with:

```sh
python3 tools/build-signed-ab-app.py \
  --variant base \
  --update-key-digest "$RISSO_KEY_TRUSTED_PUBLIC_KEY_DIGEST" \
  --secure-version 0 \
  --non-strapping-user-presence \
  --build-dir "$RISSO_KEY_AB_BUILD_ROOT/base"
```

Repeat for `failure` and `success`, then prepare the package with:

```sh
python3 tools/prepare-signed-ab-package.py \
  --espflash "$RISSO_KEY_ESPFLASH" \
  --esptool-python "$RISSO_KEY_ESPTOOL_PYTHON" \
  --bootloader-manifest "$RISSO_KEY_AB_BOOTLOADER_MANIFEST" \
  --base-manifest "$RISSO_KEY_AB_BASE_MANIFEST" \
  --failure-manifest "$RISSO_KEY_AB_FAILURE_MANIFEST" \
  --success-manifest "$RISSO_KEY_AB_SUCCESS_MANIFEST" \
  --trusted-public-key "$RISSO_KEY_TRUSTED_PUBLIC_KEY" \
  --untrusted-private-key "$RISSO_KEY_UNTRUSTED_PRIVATE_KEY" \
  --untrusted-public-key "$RISSO_KEY_UNTRUSTED_PUBLIC_KEY" \
  --security-profile wemos-s2-mini-non-strapping-up-test \
  --output-dir "$RISSO_KEY_AB_PACKAGE"
```

The package remains a reversible development-key signed A/B test. It does not
enable Secure Boot enforcement, flash encryption, ROM-download restrictions,
or any eFuse.

## Physical acceptance

The gate passes only when a disposable ESP32-S2 shows all of these results:

1. The signed application boots and completes GetInfo with GPIO16 released.
2. Pressing the built-in GPIO0 BOOT button during a pending FIDO request does
   not approve it.
3. One fresh GPIO16 press approves MakeCredential. The same credential then
   completes GetAssertion after another fresh GPIO16 press.
4. Holding GPIO16 low during reset still boots the signed application rather
   than the ROM downloader. A later USB reconnect and GetInfo must pass.
5. The built-in LED returns to idle after success, cancellation, and timeout.
6. Read-only eFuse evidence remains unchanged.

Host compilation proves only pin ownership and feature separation. It cannot
prove the board wiring, electrical level, debounce behavior, USB recovery, or
rejection of GPIO0 on physical hardware.

The disposable ESP32-S2 gate passed on 2026-09-04 with source commit
`3001ce964946dae9a9bd86297ddab15277cdae78`. GPIO0 did not approve a pending
request. Separate GPIO16 presses approved MakeCredential and GetAssertion,
holding GPIO16 through reset still booted the application, and the LED returned
to idle after success, cancellation, and timeout. The preflight and final
eFuse security fields were identical. The redacted, hash-bound result is in
[`docs/evidence/non-strapping-up-esp32s2-3001ce9.json`](../evidence/non-strapping-up-esp32s2-3001ce9.json).

Trusted firmware signing now uses the local macOS Keychain helper and requires fresh owner authentication. See [key management](../guides/key-management.md). The untrusted key remains an isolated negative-test fixture.
