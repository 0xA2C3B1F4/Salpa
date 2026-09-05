//! Development attestation checks for the mounted Trussed store.

use littlefs2::{driver::Storage, fs::Filesystem, io::Error, path::Path};
use trussed::key::{Flags, Key, Kind};
use zeroize::Zeroize as _;

use crate::identity::{DEVELOPMENT_AAGUID, certificate_aaguid, is_valid_p256_scalar};

pub const ATTESTATION_KEY_PATH: &Path = littlefs2::path!("fido/sec/00");
pub const ATTESTATION_CERT_PATH: &Path = littlefs2::path!("fido/x5c/00");

#[derive(Clone, Copy, Debug)]
pub enum DevelopmentAttestationError {
    Filesystem(Error),
    InvalidKey,
    MissingAaguid,
    UnexpectedAaguid,
}

impl From<Error> for DevelopmentAttestationError {
    fn from(error: Error) -> Self {
        Self::Filesystem(error)
    }
}

pub fn verify_development_attestation<S: Storage>(
    filesystem: &Filesystem<'_, S>,
) -> Result<(), DevelopmentAttestationError> {
    let mut serialized_key = filesystem.read::<64>(ATTESTATION_KEY_PATH)?;
    let parsed_key = Key::try_deserialize(serialized_key.as_slice());
    serialized_key.as_mut_slice().zeroize();
    let mut key = parsed_key.map_err(|_| DevelopmentAttestationError::InvalidKey)?;
    let scalar: core::result::Result<&[u8; 32], _> = key.material.as_slice().try_into();
    let valid_scalar = scalar.is_ok_and(is_valid_p256_scalar);
    let valid = key.flags == Flags::SENSITIVE
        && key.kind == Kind::P256
        && key.material.len() == 32
        && valid_scalar;
    key.zeroize();
    if !valid {
        return Err(DevelopmentAttestationError::InvalidKey);
    }

    let certificate =
        filesystem.read::<{ trussed_core::config::MAX_MESSAGE_LENGTH }>(ATTESTATION_CERT_PATH)?;
    let aaguid = certificate_aaguid(certificate.as_slice())
        .ok_or(DevelopmentAttestationError::MissingAaguid)?;
    if aaguid != DEVELOPMENT_AAGUID {
        return Err(DevelopmentAttestationError::UnexpectedAaguid);
    }

    Ok(())
}
