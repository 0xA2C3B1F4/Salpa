#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
pub mod build_environment;

pub mod ctaphid;
pub mod identity;
pub mod image_version;
pub mod request_completion;
pub mod usb_identity;

#[cfg(any(feature = "usb-signed-update", test))]
pub mod usb_update;

#[cfg(feature = "ctaphid-bringup")]
pub mod get_info;

#[cfg(all(feature = "mcu-esp32s2", feature = "mcu-esp32s3"))]
compile_error!("select exactly one MCU feature");

#[cfg(all(feature = "signed-ab-update", not(feature = "mcu-esp32s2")))]
compile_error!("signed A/B update currently supports only ESP32-S2");

#[cfg(all(feature = "usb-signed-update", not(feature = "mcu-esp32s2")))]
compile_error!("USB signed update currently supports only ESP32-S2");

#[cfg(all(feature = "release-flash-encryption", not(feature = "mcu-esp32s2")))]
compile_error!("release flash encryption currently supports only ESP32-S2");

#[cfg(all(feature = "non-strapping-user-presence", not(feature = "mcu-esp32s2")))]
compile_error!("non-strapping user presence currently supports only ESP32-S2");

#[cfg(all(not(test), not(any(feature = "mcu-esp32s2", feature = "mcu-esp32s3"))))]
compile_error!("select one MCU feature");

#[cfg(feature = "fido-stack")]
pub mod config;
#[cfg(any(feature = "fido-stack", test))]
pub mod platform;
#[cfg(feature = "usb-bringup")]
pub mod usb;
