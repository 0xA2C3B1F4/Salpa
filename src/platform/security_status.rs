//! Read-only, non-identifying eFuse status for maintenance over normal USB.
//!
//! This is a fixed allowlist of policy fields. It never reads key blocks, MAC
//! addresses, credential storage, or attestation material and has no write path.

pub const REQUEST: u8 = 0x11;
pub const RESPONSE_SIZE: usize = 32;

pub struct SecurityStatus {
    pub secure_version_raw: u16,
    pub write_disable: u32,
    pub policy_flags: u32,
    pub flash_crypt_count: u8,
    pub read_disable: u8,
    pub revoked_roots: u8,
    pub revision_major: u8,
    pub revision_minor: u8,
    pub application_secure_version: u32,
}

impl SecurityStatus {
    pub fn encode(&self, output: &mut [u8; 64]) -> usize {
        output.fill(0);
        output[..4].copy_from_slice(b"RKS1");
        output[4..6].copy_from_slice(&self.secure_version_raw.to_le_bytes());
        output[6] = self.secure_version_raw.count_ones() as u8;
        output[8..12].copy_from_slice(&self.write_disable.to_le_bytes());
        output[12..16].copy_from_slice(&self.policy_flags.to_le_bytes());
        output[16] = self.flash_crypt_count;
        output[17] = self.read_disable;
        output[18] = self.revoked_roots;
        output[19] = self.revision_major;
        output[20] = self.revision_minor;
        output[24..28].copy_from_slice(&self.application_secure_version.to_le_bytes());
        RESPONSE_SIZE
    }
}

#[cfg(all(feature = "mcu-esp32s2", not(test)))]
pub fn read(application_secure_version: u32) -> SecurityStatus {
    use esp_hal::efuse::{self, read_bit, read_field_le};

    // Keep the order in sync with the documented RKS1 flag assignments.
    let policy_fields = [
        efuse::SECURE_BOOT_EN,
        efuse::DIS_DOWNLOAD_MODE,
        efuse::DIS_USB_DOWNLOAD_MODE,
        efuse::ENABLE_SECURITY_DOWNLOAD,
        efuse::DIS_USB,
        efuse::HARD_DIS_JTAG,
    ];
    let mut policy_flags = 0;
    for (bit, field) in policy_fields.into_iter().enumerate() {
        policy_flags |= u32::from(read_bit(field)) << bit;
    }
    let revoked_roots = u8::from(read_bit(efuse::SECURE_BOOT_KEY_REVOKE0))
        | (u8::from(read_bit(efuse::SECURE_BOOT_KEY_REVOKE1)) << 1)
        | (u8::from(read_bit(efuse::SECURE_BOOT_KEY_REVOKE2)) << 2);
    SecurityStatus {
        secure_version_raw: read_field_le(efuse::SECURE_VERSION),
        write_disable: read_field_le(efuse::WR_DIS),
        policy_flags,
        flash_crypt_count: read_field_le(efuse::SPI_BOOT_CRYPT_CNT),
        read_disable: read_field_le(efuse::RD_DIS),
        revoked_roots,
        revision_major: efuse::major_chip_version(),
        revision_minor: efuse::minor_chip_version(),
        application_secure_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_reports_bit_count_and_clears_unused_bytes() {
        for raw in [0, 1, 7, 15, 0x8000, 0xffff] {
            let state = SecurityStatus {
                secure_version_raw: raw,
                write_disable: 0x01800305,
                policy_flags: 0x21,
                flash_crypt_count: 7,
                read_disable: 1,
                revoked_roots: 6,
                revision_major: 1,
                revision_minor: 0,
                application_secure_version: 4,
            };
            let mut output = [0xa5; 64];
            assert_eq!(state.encode(&mut output), 32);
            assert_eq!(&output[..4], b"RKS1");
            assert_eq!(u16::from_le_bytes(output[4..6].try_into().unwrap()), raw);
            assert_eq!(output[6], raw.count_ones() as u8);
            assert_eq!(output[7], 0);
            assert_eq!(&output[21..24], &[0; 3]);
            assert_eq!(&output[28..], &[0; 36]);
            assert_eq!(u32::from_le_bytes(output[24..28].try_into().unwrap()), 4);
        }
    }
}
