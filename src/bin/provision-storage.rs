#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    main,
    time::{Duration, Instant},
};
use littlefs2::fs::{Allocation, Filesystem};

const ARMING_WINDOW: Duration = Duration::from_secs(30);
const REQUIRED_HOLD_MS: u64 = 5_000;

esp_bootloader_esp_idf::esp_app_desc!();

// Non-secret progress only. A ROM read is useful only if the chosen reset
// preserves RTC memory. The physical EN/RESET test did not retain this record.
#[esp_hal::ram(unstable(rtc_slow, persistent))]
#[unsafe(no_mangle)]
static mut RISSO_PROVISION_DIAGNOSTIC: [u32; 4] = [0; 4];

fn milestone(stage: u32, detail: u32) {
    const MAGIC: u32 = 0x5250_4431;
    let pointer = core::ptr::addr_of_mut!(RISSO_PROVISION_DIAGNOSTIC).cast::<u32>();
    unsafe {
        core::ptr::write_volatile(pointer, 0);
        core::ptr::write_volatile(pointer.add(1), stage);
        core::ptr::write_volatile(pointer.add(2), detail);
        core::ptr::write_volatile(pointer.add(3), MAGIC ^ stage ^ detail);
        core::ptr::write_volatile(pointer, MAGIC);
    }
}

#[cfg(feature = "release-flash-encryption")]
fn initialize_encrypted_storage(led: &mut Output<'_>) {
    use salpa::platform::flash_encryption::{self, FlashEncryptionError};
    if let Err(error) = flash_encryption::initialize() {
        let (stage, detail) = match error {
            FlashEncryptionError::Disabled => (101, 0),
            FlashEncryptionError::MappingFailed(code) => (102, code as u32),
            FlashEncryptionError::UnmappedRange => (103, 0),
            FlashEncryptionError::NotAligned => (104, 0),
            FlashEncryptionError::UnlockFailed(code) => (105, code as u32),
            FlashEncryptionError::EraseFailed(code) => (106, code as u32),
            FlashEncryptionError::WriteFailed(code) => (107, code as u32),
        };
        milestone(stage, detail);
        signal_result(led, 3);
    }
}

/// Runs only after the destructive provisioner's fresh physical approval.
/// Uses the last fido_store sector and leaves it erased on success.
#[cfg(feature = "release-flash-encryption")]
fn verify_encrypted_roundtrip(led: &mut Output<'_>) {
    use salpa::platform::flash_encryption as flash;
    const ADDRESS: u32 = 0x003f_f000;
    let mut expected = [0u8; 256];
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = (index as u8) ^ 0xa5;
    }
    milestone(120, 0);
    if flash::erase(ADDRESS, 4096).is_err() {
        milestone(121, 0);
        signal_result(led, 8);
    }
    for index in 0..8 {
        if flash::write(
            ADDRESS + (index as u32 * 32),
            &expected[index * 32..index * 32 + 32],
        )
        .is_err()
        {
            milestone(122, index as u32);
            signal_result(led, 9);
        }
        let mut actual = [0u8; 256];
        let length = (index + 1) * 32;
        if flash::read(ADDRESS, &mut actual[..length]).is_err() {
            milestone(123, index as u32);
            signal_result(led, 11);
        }
        if actual[..length] != expected[..length] {
            milestone(124, index as u32);
            signal_result(led, 10);
        }
    }
    if flash::erase(ADDRESS, 4096).is_err() {
        milestone(125, 0);
        signal_result(led, 8);
    }
    milestone(126, 0);
}

// Visible result does not depend on UART output or RTC retention across EN.
fn signal_result(led: &mut Output<'_>, pulses: u32) -> ! {
    fn wait_ms(ms: u64) {
        let started = Instant::now();
        while Instant::now() - started < Duration::from_millis(ms) {
            core::hint::spin_loop();
        }
    }
    loop {
        led.set_low();
        wait_ms(2_000);
        for _ in 0..pulses {
            led.set_high();
            wait_ms(250);
            led.set_low();
            wait_ms(250);
        }
    }
}

/// Explicitly creates a fresh, empty FIDO filesystem.
///
/// This binary is excluded from normal builds. After boot it requires the
/// button to be observed released, followed by a new continuous five-second
/// press. It never runs as part of the authenticator firmware.
#[main]
fn main() -> ! {
    milestone(1, 0);
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    #[cfg(feature = "non-strapping-user-presence")]
    let button = Input::new(
        peripherals.GPIO16,
        InputConfig::default().with_pull(Pull::Up),
    );
    #[cfg(not(feature = "non-strapping-user-presence"))]
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    );
    let mut led = Output::new(peripherals.GPIO15, Level::Low, OutputConfig::default());

    milestone(2, 0);
    milestone(3, 0);
    let started = Instant::now();
    let mut gesture = salpa::platform::provisioning::ProvisioningGesture::new(REQUIRED_HOLD_MS);

    loop {
        let now = Instant::now();
        if now - started >= ARMING_WINDOW {
            milestone(100, 0);
            signal_result(&mut led, 1);
        }

        let pressed = button.is_low();
        if pressed {
            led.set_high();
        } else {
            led.set_low();
        }
        let now_ms = now.duration_since_epoch().as_millis();
        if gesture.sample(pressed, now_ms) {
            break;
        }
    }

    led.set_low();
    milestone(4, 0);
    milestone(5, 0);
    #[cfg(feature = "release-flash-encryption")]
    initialize_encrypted_storage(&mut led);
    milestone(6, 0);
    #[cfg(feature = "release-flash-encryption")]
    verify_encrypted_roundtrip(&mut led);
    let mut storage = salpa::platform::storage::FidoFlashStorage::new(peripherals.FLASH)
        .unwrap_or_else(|_| {
            milestone(114, 0);
            signal_result(&mut led, 3);
        });
    milestone(7, 0);
    Filesystem::format(&mut storage).unwrap_or_else(|error| {
        milestone(110, error.code() as u32);
        signal_result(&mut led, 4);
    });
    milestone(8, 0);

    let mut allocation = Allocation::new();
    let filesystem = Filesystem::mount(&mut allocation, &mut storage).unwrap_or_else(|_| {
        milestone(111, 0);
        signal_result(&mut led, 5);
    });
    milestone(9, 0);
    salpa::platform::storage::write_storage_version(&filesystem).unwrap_or_else(|_| {
        milestone(112, 0);
        signal_result(&mut led, 6);
    });
    milestone(10, 0);
    salpa::platform::storage::write_persistent_state_initialization_marker(&filesystem)
        .unwrap_or_else(|_| {
            milestone(113, 0);
            signal_result(&mut led, 7);
        });
    milestone(11, 0);

    milestone(12, 0);
    signal_result(&mut led, 2);
}
