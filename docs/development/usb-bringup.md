# USB FIDO HID bring-up

## Selected stack

Phase 1 uses the blocking `usb-device` integration exposed by `esp-hal` 1.1.2:

- ESP32-S2/S3 native USB OTG peripheral through `esp_hal::otg_fs`
- `usb-device` 0.3.2 for the device and interface framework
- `usbd-hid` 0.10.1 for the HID class and its standard `CtapReport` descriptor
- GPIO20 for D+ and GPIO19 for D-, as fixed by both internal USB PHYs

The HID class allocates one 64-byte interrupt IN endpoint and one 64-byte
interrupt OUT endpoint. Its default interface settings are HID subclass 0 and
protocol 0. `CtapReport` defines FIDO usage page `0xF1D0`, usage `0x01`, and
64-byte input and output reports.

An async executor is not needed for enumeration. Revisit Embassy only if
CTAPHID keepalive, cancellation, or user-presence waits become clearer with an
async design.

## Identity gate

The USB build configuration defines the strings but has no assigned production
USB VID/PID. The
`usb-bringup` feature therefore has no default identity and requires three
build-time values. It is also the only feature that enables `esp-hal`'s
unstable USB module and the two USB dependencies:

```sh
RISSO_KEY_USB_VID="$RISSO_KEY_ASSIGNED_USB_VID" \
RISSO_KEY_USB_PID="$RISSO_KEY_ASSIGNED_USB_PID" \
RISSO_KEY_USB_SERIAL="$RISSO_KEY_DEVICE_SERIAL" \
./tools/cargo-esp build --locked --features usb-bringup
```

The WEMOS S2 Mini transport-only command must explicitly disable the default
ESP32-S3 and FIDO features:

```sh
RISSO_KEY_MCU=esp32s2 \
RISSO_KEY_USB_VID="$RISSO_KEY_ASSIGNED_USB_VID" \
RISSO_KEY_USB_PID="$RISSO_KEY_ASSIGNED_USB_PID" \
RISSO_KEY_USB_SERIAL="$RISSO_KEY_DEVICE_SERIAL" \
./tools/cargo-esp build --locked --release --no-default-features \
  --features mcu-esp32s2,usb-bringup
```

VID and PID accept decimal or `0x`-prefixed hexadecimal. Zero and `0xffff`
are rejected. The serial must be a non-empty, stable per-device value. Do not
put a real device serial in source, documentation, command transcripts, or Git.
The build also rejects serials longer than 32 bytes and characters outside
ASCII letters, digits, dot, underscore, and hyphen.

No production VID/PID has been assigned in this repository. Private local
bring-up may use pid.codes' `0x1209:0x0002` test pair with the device owner's
authorization. Its published rules prohibit redistribution, sale, and
manufacture with that pair: <https://pid.codes/1209/0002/>. The test values and
the temporary per-device serial stay in the build environment rather than
source defaults.

## Board USB boundary

The WEMOS S2 Mini exposes the ESP32-S2 native USB data lines directly on its
single Type-C connector. The vendor identifies GPIO20 as D+ and GPIO19 as D-
in the board schematic. Its published board configuration is an ESP32-S2FN4R2
with 4 MB flash and 2 MB PSRAM:

- <https://www.wemos.cc/en/latest/s2/s2_mini.html>
- <https://www.wemos.cc/en/latest/_static/files/sch_s2_mini_v1.0.0.pdf>

This makes the S2 Mini the current enumeration board. One cable carries the ROM
download interface while the board is in DFU mode and the application-defined
HID device after reset; it does not provide an independent UART log channel.

The Viewe UEDX48270043E-WB-A board has two Type-C connectors. The connector
labelled `UART` goes through a CH340C and can flash the ESP32-S3, but it cannot
carry the native FIDO USB device. The connector labelled `USB` is the candidate
native path.

The vendor schematic shows optional R12/R13 links between that connector and
GPIO19/GPIO20. The same GPIOs are labelled as capacitive-touch I2C and have
4.7 kOhm pull-ups through R8/R9. Disabling the display or touch firmware does
not remove physical pull-ups. Before claiming enumeration, inspect the fitted
components or test the `USB` connector while retaining UART logs on the other
connector.

## Current evidence

The default target and `usb-bringup` checks pass with the pinned Xtensa
toolchain. The physical USB-feature build also passes release Clippy with
warnings denied. The linker emits the known warning that the ELF has an RWX
LOAD segment; this remains a separate hardening item.

The ESP32-S2 transport-only release build and release Clippy also pass with
warnings denied:

```text
Target: xtensa-esp32s2-none-elf
Board: WEMOS S2 Mini
ROM DFU identity observed by macOS: Espressif ESP32_S2, 0x303a:0x0002
ELF SHA-256: f41ed9564fc5c1d661ddf35d03325d08b8b5108d129804d96a9c2588e67fde7b
text: 48,093 bytes
data: 1,488 bytes
bss: 169,520 bytes
```

The aggregate BSS figure includes 160,844 bytes of linker-reserved `.stack`
and 3,912 bytes of `.rwdata_dummy`; the ELF's actual `.bss` section is 4,764
bytes.

The S2 firmware was flashed from clean commit `dbcd216` with DIO at 40 MHz.
`espflash` 4.5.0 identified the device but lost its native USB connection while
loading or using its RAM stub. `esptool` 5.1.0 then wrote a merged image through
the ROM loader with its stub disabled and verified the data hash before a
watchdog reset:

```text
Target: WEMOS S2 Mini, ESP32-S2FNR2 revision v1.0
Observed flash: 4 MB embedded flash, 2 MB embedded PSRAM
Flash transport: native USB ROM loader on the board's only Type-C connector
Merged image: 163,728 bytes at 0x0
Merged image SHA-256: 01711aef944164d4040059d30d37acd9b0b04caeb8ffa769f411090eb5e01b74
Write span: 163,840 bytes at 0x0
Flash result: write completed and data hash verified
```

After reset, the ROM serial device disappeared and macOS attached its USB and
HID drivers to the application:

```text
Manufacturer: Rissotek
Product: Rissotek Security Key
VID:PID: 0x1209:0x0002, private bring-up only
USB device class: 0
HID interface class: 3
HID usage page: 0xF1D0
HID usage: 0x01
Maximum input report: 64 bytes
Maximum output report: 64 bytes
Polling interval: 4 ms
```

This passes the first physical enumeration and descriptor gate with one cable.
On macOS, the project-owned `tools/hid-out-probe.c` then opened the device by
an explicitly supplied VID/PID and completed one 64-byte output report carrying
a valid CTAPHID INIT frame. Build and run it without putting identity values in
the executable:

```sh
clang -Wall -Wextra -Werror -framework IOKit -framework CoreFoundation \
  -o "$TMPDIR/rissokey-hid-out-probe" tools/hid-out-probe.c
"$TMPDIR/rissokey-hid-out-probe" \
  "$RISSO_KEY_ASSIGNED_USB_VID" "$RISSO_KEY_ASSIGNED_USB_PID"
```

The host write returned success. A hardware reset then created a new macOS USB
session with the same VID/PID, product strings, usage page, usage, and 64-byte
report sizes. The 64-byte OUT probe also passed after that re-enumeration.

The transport-only firmware used for these first checks consumed and discarded
the report. It was later replaced with the CTAPHID and narrow GetInfo build
documented in `ctaphid-bringup.md`. That build proves device-to-host reports,
fragmented PING, and GetInfo on the same physical S2 Mini. A physical disconnect
and reconnect cycle remains open.

The S2 `fido-stack` compatibility gate later passed with the narrow vendored
patches recorded in `dependency-spike.md`. They use `portable-atomic` through
the single-core implementation selected by `esp-hal`; no false Rust target
capability override is used.

Physical test record on macOS 26.5.2 (build 25F84):

```text
Target: Viewe UEDX48270043E-WB-A, ESP32-S3 revision v0.2
Observed flash: 16 MB
Flash transport: CH340C UART
ELF SHA-256: 7b8ee1b2c006fcd5b760c67b00a60409bcf91ecbc6b8ee1b802625a8f1092eb5
Application image: 99,936 bytes at 0x10000
Application SHA-256: 2861c5edd62d240bd62eaca2f8df036c689eef12f03a1dbd6ca57f7aebb57d2b
```

With QIO at 80 MHz, the ROM loaded only the first second-stage bootloader
segment and then alternated timer-group and RTC watchdog resets. No
`RISSO_STAGE: entry` marker appeared, so the failure preceded the Rust entry
point and USB initialization.

Reflashing the same ELF as DIO at 40 MHz booted the second-stage loader and
application. UART reached every marker from `RISSO_STAGE: entry` through
`RISSO_STAGE: poll-loop` without another reset. A readback of the full
99,936-byte application region matched the generated image byte for byte and
had the SHA-256 shown above. This proves the flashed application bytes and a
stable post-reset USB polling loop on this board. It does not prove the
separate native USB connector.

The first native-connector test used one cable. Moving it from `UART` to `USB`
removed the CH340 serial device from macOS, but no Rissotek device, test
VID/PID, unknown USB device, or USB enumeration error appeared. This is a
failed enumeration result, not proof that the firmware descriptors are wrong.
It matches the vendor's reference PCB photo, where R12/R13 appear unpopulated
and therefore leave the native USB data lines disconnected. The fitted parts
on the tested board still require visual or continuity inspection.

Still not proven on the WEMOS S2 Mini:

- stable per-device serial generation
- physical disconnect and reconnect cycle
- 64-byte device-to-host transfers
- CTAPHID or FIDO behavior

The next gate is a repeated reconnect test followed by 64-byte HID transfers.
The private test VID/PID is not a production identity. The Viewe board's
R12/R13 population and touch-bus conflict remain unresolved hardware work; do
not fit those links without checking R8/R9 and the touch-controller connection.
