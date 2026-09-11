//! Bounded, certificate-bound staging format for the separate import image.
use sha2::{Digest, Sha256};

pub const STAGING_ADDRESS: u32 = 0x0020_0000;
pub const STAGING_BYTES: usize = 4096;
pub const MAX_CERTIFICATE_BYTES: usize = 1024;

pub struct Identity<'a> {
    pub key: &'a [u8; 32],
    pub certificate: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidPayload {
    Format,
    Certificate,
    Key,
}

pub fn parse<'a>(
    data: &'a [u8; STAGING_BYTES],
    expected_certificate: &[u8; 32],
) -> Result<Identity<'a>, InvalidPayload> {
    if &data[..8] != b"RKATST01" || data[12..16] != [0; 4] {
        return Err(InvalidPayload::Format);
    }
    let length = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_CERTIFICATE_BYTES || data[48 + length..].iter().any(|b| *b != 0)
    {
        return Err(InvalidPayload::Format);
    }
    let certificate = &data[48..48 + length];
    let digest: [u8; 32] = Sha256::digest(certificate).into();
    if digest != *expected_certificate
        || crate::identity::certificate_aaguid(certificate)
            != Some(crate::identity::DEVELOPMENT_AAGUID)
    {
        return Err(InvalidPayload::Certificate);
    }
    let key: &[u8; 32] = data[16..48].try_into().unwrap();
    if !crate::identity::is_valid_p256_scalar(key) {
        return Err(InvalidPayload::Key);
    }
    Ok(Identity { key, certificate })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> ([u8; STAGING_BYTES], [u8; 32]) {
        // Public scalar 1 and synthetic AAGUID fixture, never a device key.
        let mut data = [0; STAGING_BYTES];
        data[..8].copy_from_slice(b"RKATST01");
        data[8..12].copy_from_slice(&33u32.to_le_bytes());
        data[47] = 1;
        data[48..65].copy_from_slice(&[6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 1, 1, 4, 4, 18, 4, 16]);
        data[65..81].copy_from_slice(&crate::identity::DEVELOPMENT_AAGUID);
        let digest = Sha256::digest(&data[48..81]).into();
        (data, digest)
    }
    #[test]
    fn accepts_bound_payload() {
        let (d, h) = fixture();
        assert_eq!(parse(&d, &h).unwrap().key[31], 1);
    }
    #[test]
    fn rejects_wrong_certificate_reference() {
        let (d, _) = fixture();
        assert!(matches!(
            parse(&d, &[0; 32]),
            Err(InvalidPayload::Certificate)
        ));
    }
    #[test]
    fn rejects_bad_lengths_without_slicing_outside_buffer() {
        for length in [0, 1025, u32::MAX] {
            let (mut d, h) = fixture();
            d[8..12].copy_from_slice(&length.to_le_bytes());
            assert!(matches!(parse(&d, &h), Err(InvalidPayload::Format)));
        }
    }
    #[test]
    fn rejects_corruption_and_unexpected_padding() {
        for offset in [0, 12, 4095] {
            let (mut d, h) = fixture();
            d[offset] ^= 1;
            assert!(matches!(parse(&d, &h), Err(InvalidPayload::Format)));
        }
    }
    #[test]
    fn rejects_zero_private_scalar() {
        let (mut d, h) = fixture();
        d[47] = 0;
        assert!(matches!(parse(&d, &h), Err(InvalidPayload::Key)));
    }
    #[test]
    fn rejects_wrong_aaguid_even_with_matching_hash() {
        let (mut d, _) = fixture();
        d[80] ^= 1;
        let h = Sha256::digest(&d[48..81]).into();
        assert!(matches!(parse(&d, &h), Err(InvalidPayload::Certificate)));
    }
}
