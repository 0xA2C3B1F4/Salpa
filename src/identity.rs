//! Public development identity shared by GetInfo and attestation provisioning.

/// Public, development-only AAGUID for RissoKey bring-up firmware.
///
/// The AAGUID is not secret. It must be replaced together with the attestation
/// identity before any production use.
pub const DEVELOPMENT_AAGUID: [u8; 16] = [
    0x98, 0x9e, 0x2c, 0xc2, 0x05, 0xdf, 0x4e, 0x64, 0x80, 0x68, 0x22, 0x68, 0x38, 0x86, 0xe8, 0xb3,
];

// DER encoding of OID 1.3.6.1.4.1.45724.1.1.4 followed by the X.509
// extension's outer and inner OCTET STRING headers. This is the encoding the
// pinned fido-authenticator Identity implementation recognizes.
const AAGUID_EXTENSION_PREFIX: [u8; 17] = [
    0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04, 0x04, 0x12, 0x04,
    0x10,
];

const P256_GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

pub fn certificate_aaguid(der: &[u8]) -> Option<[u8; 16]> {
    let prefix_start = der
        .windows(AAGUID_EXTENSION_PREFIX.len())
        .position(|window| window == AAGUID_EXTENSION_PREFIX)?;
    let value_start = prefix_start + AAGUID_EXTENSION_PREFIX.len();
    der.get(value_start..value_start + 16)?.try_into().ok()
}

pub fn is_valid_p256_scalar(raw: &[u8; 32]) -> bool {
    raw.iter().any(|byte| *byte != 0) && raw < &P256_GROUP_ORDER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_development_aaguid_from_expected_der_shape() {
        let mut der = [0_u8; 37];
        der[2..19].copy_from_slice(&AAGUID_EXTENSION_PREFIX);
        der[19..35].copy_from_slice(&DEVELOPMENT_AAGUID);

        assert_eq!(certificate_aaguid(&der), Some(DEVELOPMENT_AAGUID));
    }

    #[test]
    fn rejects_missing_or_truncated_extension() {
        assert_eq!(certificate_aaguid(&[0_u8; 64]), None);

        let mut truncated = [0_u8; 32];
        truncated[..17].copy_from_slice(&AAGUID_EXTENSION_PREFIX);
        assert_eq!(certificate_aaguid(&truncated), None);
    }

    #[test]
    fn returns_the_certificate_value_not_a_compiled_in_default() {
        let different = [0x5a; 16];
        let mut der = [0_u8; 33];
        der[..17].copy_from_slice(&AAGUID_EXTENSION_PREFIX);
        der[17..].copy_from_slice(&different);

        assert_eq!(certificate_aaguid(&der), Some(different));
    }

    #[test]
    fn accepts_nonzero_scalar_below_the_group_order() {
        let mut one = [0_u8; 32];
        one[31] = 1;
        assert!(is_valid_p256_scalar(&one));

        let mut order_minus_one = P256_GROUP_ORDER;
        order_minus_one[31] -= 1;
        assert!(is_valid_p256_scalar(&order_minus_one));
    }

    #[test]
    fn rejects_zero_and_scalars_at_or_above_the_group_order() {
        assert!(!is_valid_p256_scalar(&[0_u8; 32]));
        assert!(!is_valid_p256_scalar(&P256_GROUP_ORDER));
        assert!(!is_valid_p256_scalar(&[0xff; 32]));
    }
}
