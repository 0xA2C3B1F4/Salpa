#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is not safe for HAL values that own hardware resources"
)]
#![deny(clippy::large_stack_frames)]

#[cfg(feature = "attestation-import")]
compile_error!("attestation-import must use the separate import-attestation binary");

#[cfg(feature = "firmware-diagnostics")]
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::main;

esp_bootloader_esp_idf::esp_app_desc!(
    salpa::image_version::APP_VERSION,
    env!("CARGO_PKG_NAME"),
    esp_bootloader_esp_idf::BUILD_TIME,
    esp_bootloader_esp_idf::BUILD_DATE,
    esp_bootloader_esp_idf::ESP_IDF_COMPATIBLE_VERSION,
    esp_bootloader_esp_idf::MMU_PAGE_SIZE,
    0,
    u16::MAX,
    esp_bootloader_esp_idf::SECURE_VERSION
);

#[cfg(all(feature = "usb-bringup", feature = "firmware-diagnostics"))]
macro_rules! firmware_log {
    ($($argument:tt)*) => {
        esp_println::println!($($argument)*);
    };
}

#[cfg(all(feature = "usb-bringup", not(feature = "firmware-diagnostics")))]
macro_rules! firmware_log {
    ($($argument:tt)*) => {};
}

mod startup;

#[cfg(not(feature = "firmware-diagnostics"))]
#[panic_handler]
fn panic_without_diagnostics(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[allow(
    clippy::large_stack_frames,
    reason = "embedded entry points may need larger local buffers during bring-up"
)]
#[main]
fn main() -> ! {
    // Based on esp-generate 1.3.0 with ESP32-S2/S3 and esp-backtrace options.
    #[cfg(feature = "usb-bringup")]
    firmware_log!("RISSO_STAGE: entry");

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    #[cfg(all(
        feature = "mcu-esp32s2",
        feature = "release-flash-encryption",
        feature = "fido-stack"
    ))]
    salpa::platform::memory_protection::initialize()
        .expect("memory protection configuration failed");
    #[cfg(feature = "usb-bringup")]
    firmware_log!("RISSO_STAGE: hal-ready");

    startup::run(peripherals)
}
