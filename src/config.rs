use fido_authenticator::{Config, FirmwareVersion, credential::CredentialIdVersion};

const FIRMWARE_MAJOR: usize = 0;
const FIRMWARE_MINOR: usize = 1;
const FIRMWARE_PATCH: usize = crate::image_version::FIRMWARE_PATCH;

pub const FIRMWARE_VERSION: usize = (FIRMWARE_MAJOR << 22) | (FIRMWARE_MINOR << 6) | FIRMWARE_PATCH;

pub const fn fido_config() -> Config {
    Config {
        max_msg_size: crate::ctaphid::MAX_MESSAGE_SIZE,
        skip_up_timeout: None,
        max_resident_credential_count: Some(8),
        large_blobs: None,
        nfc_transport: false,
        ccid_transport: false,
        firmware_version: Some(FirmwareVersion {
            default: FIRMWARE_VERSION,
            credential_id_v1: None,
            credential_id_v2: None,
        }),
        credential_id_version: Some(CredentialIdVersion::V2),
        long_touch_for_reset: false,
        fido2_up_timeout: None,
    }
}

const _: () = {
    let config = fido_config();
    assert!(!config.nfc_transport);
    assert!(!config.ccid_transport);
    assert!(config.large_blobs.is_none());
    assert!(matches!(
        config.credential_id_version,
        Some(CredentialIdVersion::V2)
    ));
};
