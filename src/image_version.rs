//! Build identities used to distinguish signed A/B acceptance images.

#[cfg(all(feature = "signed-ab-failure-test", feature = "signed-ab-success-test"))]
compile_error!("select at most one signed A/B test image");

#[cfg(feature = "signed-ab-failure-test")]
pub const APP_VERSION: &str = "0.1.1-ab-fail";
#[cfg(feature = "signed-ab-success-test")]
pub const APP_VERSION: &str = "0.1.2-ab-pass";
#[cfg(feature = "security-epoch-preview")]
pub const APP_VERSION: &str = "0.1.3-epoch-preview";
#[cfg(feature = "security-epoch-maintenance")]
pub const APP_VERSION: &str = "0.1.5-epoch-maint";
#[cfg(not(any(
    feature = "signed-ab-failure-test",
    feature = "signed-ab-success-test",
    feature = "security-epoch-preview",
    feature = "security-epoch-maintenance"
)))]
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "signed-ab-failure-test")]
pub const FIRMWARE_PATCH: usize = 1;
#[cfg(feature = "signed-ab-success-test")]
pub const FIRMWARE_PATCH: usize = 2;
#[cfg(feature = "security-epoch-preview")]
pub const FIRMWARE_PATCH: usize = 3;
#[cfg(feature = "security-epoch-maintenance")]
pub const FIRMWARE_PATCH: usize = 5;
#[cfg(not(any(
    feature = "signed-ab-failure-test",
    feature = "signed-ab-success-test",
    feature = "security-epoch-preview",
    feature = "security-epoch-maintenance"
)))]
pub const FIRMWARE_PATCH: usize = 0;

/// The failure image must never cancel rollback.
pub const CONFIRM_SIGNED_UPDATE: bool = !cfg!(feature = "signed-ab-failure-test");
