# Bring-up notes

## Hardware record

The first physical target is a Viewe 4.3-inch development display. The display,
touch UI, Wi-Fi, and BLE are outside RissoKey's current scope.

```text
Board: Viewe UEDX48270043E-WB-A
ESP32-S3: revision v0.2 observed by espflash
Flash size: 16 MB observed by espflash
PSRAM: 8 MB stated by the vendor; not used or probed by RissoKey
Flash/UART connector: Type-C connector labelled UART, through CH340C
Native USB connector: separate Type-C connector labelled USB
Button GPIO and active level: not yet selected
LED GPIO and active level: not yet selected
Board serial or inventory identifier: not recorded in Git
```

The vendor product page and datasheet identify the module family and memory
configuration:

- <https://viewedisplay.com/product/esp32-4-3-inch-480x272-rgb-ips-tft-display-touch-screen-arduino-lvgl-wifi-ble-uart-smart-module/>
- <https://viewedisplay.com/download/73/smart-display-datasheet/6566/uedx48270043e-wb-a-v2-0-spec-2.pdf>

The vendor schematic in commit `17c3f1cd56eda8f72182895d73143dc06a588bfc`
shows that the UART connector terminates at a CH340C, not the ESP32-S3 native
USB peripheral. The separate USB connector reaches the native USB nets through
the optional R12/R13 links. Those nets share GPIO19/GPIO20 with the capacitive
touch I2C bus and its R8/R9 4.7 kOhm pull-ups. The vendor's reference PCB photo
shows R12/R13 unpopulated. Component population on this physical board has not
yet been inspected, so routing and electrical compatibility remain an open
hardware gate. Do not infer native USB behavior from the generic ESP32-S3 pin
assignment alone.

Schematic source:
<https://github.com/VIEWESMART/UEDX48270043E-ESP32-4.3inch-Touch-Display/tree/17c3f1cd56eda8f72182895d73143dc06a588bfc/Schematic>

Reference PCB photo:
<https://github.com/VIEWESMART/UEDX48270043E-ESP32-4.3inch-Touch-Display/blob/17c3f1cd56eda8f72182895d73143dc06a588bfc/image/Layout.png>

The current USB enumeration target is a WEMOS S2 Mini. Its single Type-C
connector exposes the native ESP32-S2 USB peripheral. macOS first observed its
ESP32-S2FNR2 ROM downloader at `0x303a:0x0002`, with 4 MB embedded flash and
2 MB embedded PSRAM. After flashing, the same connector enumerated the
application as a FIDO-shaped HID device. The exact record is in
`usb-bringup.md`. Its BOOT button is active-low GPIO0. The built-in LED is
active-high GPIO15 according to the official v1.0.0 schematic: GPIO15 drives
the LED through a 2 kOhm resistor to ground.

Schematic source:
<https://www.wemos.cc/en/latest/_static/files/sch_s2_mini_v1.0.0.pdf>

## Toolchain record

Record the exact installed versions and commands after the dependency spike:

```text
Rust toolchain: Espressif 1.97.0.0, rustc commit 8ea53bcd7
Compilation targets: xtensa-esp32s3-none-elf and xtensa-esp32s2-none-elf
esp-hal: 1.1.2
espflash: 4.5.0, isolated under the task scratch directory
esptool: 5.1.0, host installation used for ESP32-S2 ROM flashing
Linker/build runner: xtensa-esp-elf GCC 15.2.0; runner reserved for espflash
fido-authenticator revision:
ctap-types revision:
Trussed revision:
ctaphid-dispatch revision:
usb-device: 0.3.2
usbd-hid: 0.10.1
```

The project toolchain is isolated under the task scratch directory. It does not
change the host's Homebrew Rust or shell profile. `espflash` is an isolated
download rather than a host-wide installation. `probe-rs` and `fido2-token`
remain uninstalled.

After sourcing the export file created by `espup`, use the repository wrapper so C dependencies and bindgen see the same Xtensa headers:

```sh
RISSO_KEY_BUILD_ROOT="$TMPDIR/rissokey-build"
mkdir -p "$RISSO_KEY_BUILD_ROOT"
CARGO_TARGET_DIR="$RISSO_KEY_BUILD_ROOT/target" ./tools/cargo-esp check --locked
```

The wrapper defaults `CARGO_TARGET_DIR` to `$TMPDIR/rissokey-target` when the caller does not set it.

The USB feature, private test identity, connector boundary, and physical
evidence are described in `usb-bringup.md`.

## Evidence gates

For every physical-device phase, record:

- firmware commit and dirty state
- exact build command
- flashed artifact checksum
- board identity
- host and OS version
- verification command and result
- whether the observation survived reconnect or reset

A build result is not USB evidence. USB enumeration is not CTAP evidence. `GetInfo` is not credential evidence. Browser registration is not persistence evidence. OpenAI enrollment is not later authentication evidence.
