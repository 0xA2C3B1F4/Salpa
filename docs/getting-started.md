# Getting started

Use macOS or Linux for host development. No board, account, operational key, or
Keychain access is required for the tests and compile checks on this page.
Clone the public repository, then run the commands from its root.

## Prerequisites

- Python 3.12 or later, with venv support.
- Git, Rustup, and a C compiler. macOS needs Xcode Command Line Tools. Linux
  needs the usual compiler/build tools, pkg-config, and OpenSSL development
  headers for installing the Rust tools.
- An existing writable `TMPDIR`, with enough space for the compiler and build
  output. Use an external task directory for long-lived or large local builds.

Install the host dependencies into a directory outside the repository:

```sh
python3 -m venv "$TMPDIR/salpa-venv"
. "$TMPDIR/salpa-venv/bin/activate"
export PIP_CACHE_DIR="$TMPDIR/salpa-pip-cache"
python3 -m pip install --require-hashes --only-binary=:all: -r requirements-build.txt
python3 -m pip install --require-hashes --no-build-isolation -r requirements-dev.txt
python3 -m pip check
rustup toolchain install 1.97.0 --profile minimal --component rustfmt
export PYTHONDONTWRITEBYTECODE=1
export CARGO_TARGET_DIR="$TMPDIR/salpa-host-target"
```

See [Python dependency locking](development/python-dependencies.md) for updates
and platform validation.

## Host tests

For a public checkout, verify the exported file set and hashes first:

```sh
python3 scripts/check_public_tree.py export .
python3 scripts/check_public_history.py
```

In the private development source, use `check_public_tree.py source` instead.
Then run the common checks:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/check_partition_layouts.py
python3 scripts/check_efuse_plan.py --self-test
python3 scripts/check_security_profiles.py
RUSTUP_TOOLCHAIN=1.97.0 cargo fmt --all -- --check
host_target=$(rustc +1.97.0 -vV | sed -n 's/^host: //p')
RUSTUP_TOOLCHAIN=1.97.0 cargo test --lib --locked --target "$host_target" --no-default-features
RUSTUP_TOOLCHAIN=1.97.0 ./tools/test-storage-faults
RUSTUP_TOOLCHAIN=1.97.0 ./tools/test-persistent-state
```

On macOS, also run `python3 tools/macos-key-helper/test-crypto.py`. It compiles
the helper's test entry point and uses disposable fixtures. It does not install
the helper, read the operational Keychain, or show authentication prompts.

## ESP32 compile checks

Install the pinned Espressif toolchain without changing the host default:

```sh
CARGO_TARGET_DIR="$TMPDIR/salpa-espup-build" cargo +1.97.0 install espup --locked --version 0.17.1
espup install --targets esp32s2,esp32s3 --toolchain-version 1.97.0.0 \
  --name esp-1.97.0.0 --export-file "$TMPDIR/salpa-export-esp.sh"
. "$TMPDIR/salpa-export-esp.sh"
python3 tools/check-firmware-builds.py --build-dir "$TMPDIR/salpa-compile-check"
```

Choose a new build directory. The command links and runs Clippy with
`-D warnings` on S2 development, protected S2, S3 bring-up, attestation import,
storage provisioning, development provisioning and storage power-cut tests.
Use `--profile` to select one configuration or `--check build` / `--check clippy`
for one check type. It supplies public fixture inputs, including a synthetic
USB identity and signing digest. The development provisioner gets known
scalar-one bytes and an invalid certificate-shaped fixture, not a generated
attestation identity. Outputs are
compile checks only. Do not flash them. The S3 result proves compilation and
linking, not a complete physical authenticator.

## Hardware work is a separate step

The accepted WEMOS S2 Mini uses native USB on GPIO19/20, an active-low button
between GPIO16 and GND for protected firmware, and the GPIO15 LED. GPIO0/BOOT
selects ROM download and is the presence button only in the older development
profile. The project does not have an assigned production USB VID/PID; the
compile fixtures are not an assignment. See [USB bring-up](development/usb-bringup.md).

Before provisioning, identify the exact board and profile, establish recoverable
attestation assets, and review the [key-management](guides/key-management.md) and
[attestation-recovery](guides/attestation-recovery.md) procedures. Protected bootloader
images can change eFuses on first boot. Building an image is not permission to
install it. Never erase or provision an enrolled account key as a test shortcut.

Normal signed updates use the [USB update procedure](guides/usb-signed-update.md).
Irreversible settings and final ROM restrictions have a separate
[release-hardening process](plans/release-hardening.md).


## Build input names

Use `SALPA_*` environment variables, for example `SALPA_MCU`, `SALPA_USB_VID`,
`SALPA_USB_PID` and `SALPA_USB_SERIAL`. The corresponding `RISSO_KEY_*` aliases
remain accepted by the build tools. If both names are set, their values must
match; conflicting inputs stop the operation without printing their values.
Private USB identity JSON files accept the same aliases without rewriting the
original file. Clear both names when removing an acknowledgement or input.

Storage markers, package schemas, backup identifiers, installed Keychain helper
paths and diagnostic log markers retain their existing values for compatibility.
