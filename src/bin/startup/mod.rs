//! Select the runtime after HAL and, for protected S2, PMS initialization.

#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
mod s2_fido;
#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
pub(super) use s2_fido::run;

#[cfg(all(
    feature = "usb-bringup",
    not(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "ctaphid-bringup"
    ))
))]
mod usb_bringup;

#[cfg(feature = "usb-bringup")]
static mut USB_ENDPOINT_MEMORY: [u32; 1024] = [0; 1024];

#[cfg(not(all(feature = "fido-stack", feature = "mcu-esp32s2")))]
#[inline(always)]
pub(super) fn run(peripherals: esp_hal::peripherals::Peripherals) -> ! {
    #[cfg(feature = "fido-stack")]
    let fido_config = salpa::config::fido_config();
    #[cfg(feature = "fido-stack")]
    let hardware_rng = {
        let source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
        let mut rng = salpa::platform::rng::HardwareRng::new(source)
            .expect("ESP hardware entropy source was not enabled");
        rng.startup_sanity_check()
            .expect("ESP hardware RNG failed startup sanity check");
        rng
    };

    #[cfg(feature = "fido-stack")]
    let _ = (&hardware_rng, fido_config);
    #[cfg(all(feature = "usb-bringup", feature = "fido-stack"))]
    firmware_log!("RISSO_STAGE: fido-config-ready");
    #[cfg(all(feature = "usb-bringup", not(feature = "fido-stack")))]
    firmware_log!("RISSO_STAGE: fido-stack-disabled");

    #[cfg(feature = "usb-bringup")]
    usb_bringup::run(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);
    #[cfg(not(feature = "usb-bringup"))]
    {
        #[cfg(not(feature = "fido-stack"))]
        let _ = peripherals;
        idle()
    }
}

#[cfg(not(feature = "usb-bringup"))]
fn idle() -> ! {
    use esp_hal::time::{Duration, Instant};
    loop {
        let delay_start = Instant::now();
        while delay_start.elapsed() < Duration::from_millis(500) {}
    }
}
