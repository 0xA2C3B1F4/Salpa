//! Deliberately narrow CTAP2 bring-up dispatcher.
//!
//! The only successful operation is `authenticatorGetInfo`. Encoding and
//! request parsing come from the pinned upstream `ctap-types` crate. Credential
//! operations remain disabled until the Trussed platform services are wired.

use ctap_types::{
    Vec,
    ctap2::{
        Error, Request, Response,
        get_info::{CtapOptions, ResponseBuilder, Transport, Version},
    },
};

pub const MAX_MESSAGE_SIZE: usize = crate::ctaphid::MAX_MESSAGE_SIZE;
pub const MAX_RESPONSE_SIZE: usize = 256;

/// Public, development-only AAGUID for the Salpa bring-up firmware.
///
/// This is not attestation key material and must be revisited before any
/// production authenticator identity is provisioned.
pub use crate::identity::DEVELOPMENT_AAGUID;

pub fn dispatch(request: &[u8]) -> Vec<u8, MAX_RESPONSE_SIZE> {
    match Request::deserialize(request) {
        Ok(Request::GetInfo) => get_info_response(),
        Ok(_) => error_response(Error::InvalidCommand),
        Err(error) => error_response(error),
    }
}

fn get_info_response() -> Vec<u8, MAX_RESPONSE_SIZE> {
    let mut versions = Vec::new();
    versions.push(Version::Fido2_0).ok();

    let mut response = ResponseBuilder {
        versions,
        aaguid: DEVELOPMENT_AAGUID.into(),
    }
    .build();

    let mut options = CtapOptions::default();
    options.plat = Some(false);
    response.options = Some(options);
    response.max_msg_size = Some(MAX_MESSAGE_SIZE);

    let mut transports = Vec::new();
    transports.push(Transport::Usb).ok();
    response.transports = Some(transports);

    let mut encoded = Vec::new();
    Response::GetInfo(response).serialize(&mut encoded);
    encoded
}

fn error_response(error: Error) -> Vec<u8, MAX_RESPONSE_SIZE> {
    let mut encoded = Vec::new();
    encoded.push(error as u8).ok();
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_is_the_only_successful_operation() {
        let get_info = dispatch(&[0x04]);
        assert_eq!(get_info.first(), Some(&0x00));
        assert!(get_info.len() > 17);

        let reset = dispatch(&[0x07]);
        assert_eq!(reset.as_slice(), &[Error::InvalidCommand as u8]);
    }

    #[test]
    fn malformed_request_uses_upstream_error_mapping() {
        let empty = dispatch(&[]);
        assert_eq!(empty.as_slice(), &[Error::InvalidCbor as u8]);
    }
}
