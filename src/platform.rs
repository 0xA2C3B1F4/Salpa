//! ESP platform services needed by Trussed.

#[cfg(feature = "fido-stack")]
pub mod attestation;
#[cfg(any(feature = "attestation-import", test))]
pub mod attestation_import;
#[cfg(feature = "fido-stack")]
pub mod dispatch;
#[cfg(any(feature = "release-flash-encryption", test))]
pub mod flash_encryption;
pub mod ota;
#[cfg(any(
    feature = "storage-provisioning",
    feature = "attestation-import",
    feature = "physical-storage-fault-test",
    test
))]
pub mod provisioning;
#[cfg(feature = "fido-stack")]
pub mod rng;
pub mod rng_health;
#[cfg(feature = "fido-stack")]
pub mod runtime;
#[cfg(feature = "fido-stack")]
pub mod storage;
#[cfg(feature = "fido-stack")]
pub mod storage_init;
pub mod storage_layout;
#[cfg(feature = "usb-signed-update")]
pub mod usb_update;

#[cfg(feature = "mcu-esp32s2")]
pub mod s2_user_presence;
#[cfg(all(
    feature = "mcu-esp32s2",
    feature = "usb-bringup",
    feature = "ctaphid-bringup"
))]
pub mod usb_runtime;
pub mod user_presence;
