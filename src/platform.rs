//! ESP platform services needed by Trussed.

#[cfg(feature = "fido-stack")]
pub mod attestation;
#[cfg(any(feature = "attestation-import", test))]
pub mod attestation_import;
#[cfg(feature = "fido-stack")]
pub mod dispatch;
#[cfg(any(feature = "release-flash-encryption", test))]
pub mod flash_encryption;
#[cfg(any(feature = "security-epoch-maintenance", test))]
pub mod maintenance_presence;
#[cfg(any(
    all(feature = "release-flash-encryption", feature = "fido-stack"),
    test
))]
pub mod memory_protection;
#[cfg(any(feature = "signed-ab-update", test))]
pub mod ota;
pub mod presence_gate;
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
#[cfg(any(feature = "signed-ab-update", test))]
pub mod security_epoch;
#[cfg(any(feature = "security-epoch-maintenance", test))]
pub mod security_epoch_plan;
#[cfg(any(
    feature = "security-epoch-preview",
    feature = "security-epoch-maintenance",
    test
))]
pub mod security_epoch_preview;
#[cfg(any(feature = "security-epoch-maintenance", test))]
pub mod security_epoch_transaction;
#[cfg(any(feature = "usb-signed-update", test))]
pub mod security_status;
#[cfg(feature = "fido-stack")]
pub mod storage;
#[cfg(feature = "fido-stack")]
pub mod storage_init;
pub mod storage_layout;
#[cfg(feature = "usb-signed-update")]
pub mod usb_update;

#[cfg(all(
    feature = "mcu-esp32s2",
    feature = "security-epoch-maintenance",
    not(test)
))]
mod s2_epoch_programmer;
#[cfg(feature = "mcu-esp32s2")]
pub mod s2_user_presence;
#[cfg(all(
    feature = "mcu-esp32s2",
    feature = "security-epoch-maintenance",
    not(test)
))]
pub mod security_epoch_maintenance;
#[cfg(all(
    feature = "mcu-esp32s2",
    feature = "usb-bringup",
    feature = "ctaphid-bringup"
))]
pub mod usb_runtime;
pub mod user_presence;
