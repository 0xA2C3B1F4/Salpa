//! ESP32-S2 signed-image parsing and read-only installed-slot verification.

use sha2::{Digest, Sha256};

pub const OTA_SLOT_SIZE: u32 = 0x1e_0000;
pub const SIGNATURE_SECTOR_SIZE: u32 = 0x1000;
pub const SIGNATURE_BLOCK_SIZE: usize = 1216;
pub const SIGNATURE_CRC_LENGTH: usize = 1196;
pub const RSA_PUBLIC_KEY_SIZE: usize = 776;
pub const RSA_SIGNATURE_SIZE: usize = 384;
pub const MAX_VERSION_LENGTH: usize = 31;

const ESP_IMAGE_MAGIC: u8 = 0xe9;
const ESP32S2_CHIP_ID: u16 = 2;
const ESP_APP_DESCRIPTOR_MAGIC: u32 = 0xabcd_5432;
const SECURE_BOOT_V2_SIGNATURE_MAGIC: u8 = 0xe7;
const SECURE_BOOT_V2_RSA_VERSION: u8 = 2;
const APP_DESCRIPTOR_OFFSET: u32 = 32;
pub(crate) const APP_DESCRIPTOR_PREFIX_SIZE: usize = 80;
const APP_SECURE_VERSION_OFFSET: usize = 4;
const APP_VERSION_OFFSET: usize = 16;

/// Read and authenticate an image. This interface cannot erase, write or activate a slot.
pub trait ImageReader {
    type Error;

    fn read(&mut self, slot: u8, offset: u32, output: &mut [u8]) -> Result<(), Self::Error>;
    fn verify_rsa_pss(
        &mut self,
        public_key: &[u8; RSA_PUBLIC_KEY_SIZE],
        signature: &[u8; RSA_SIGNATURE_SIZE],
        image_digest: &[u8; 32],
    ) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledImageError {
    Slot,
    Read,
    Header,
    Extent,
    Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedInstalledImage {
    pub secure_version: u32,
    pub signed_image_bytes: u32,
    pub signed_content_digest: [u8; 32],
}

/// Verify an installed slot without erasing, writing or selecting it.
/// The bounded ESP image layout determines the signature location; a caller
/// cannot supply a shorter length that omits part of the installed image.
/// This authenticates its contents, but does not prove that they boot. Before
/// raising an epoch, bind the returned digest to independent boot evidence.
pub fn verify_installed_slot<B: ImageReader>(
    backend: &mut B,
    slot: u8,
    trusted_key_digest: &[u8; 32],
) -> Result<VerifiedInstalledImage, InstalledImageError> {
    if slot > 1 {
        return Err(InstalledImageError::Slot);
    }
    let mut prefix = [0; APP_DESCRIPTOR_PREFIX_SIZE];
    backend
        .read(slot, 0, &mut prefix)
        .map_err(|_| InstalledImageError::Read)?;
    let metadata = parse_image_metadata(&prefix).ok_or(InstalledImageError::Header)?;
    if prefix[23] != 1 || metadata.secure_version > 16 {
        return Err(InstalledImageError::Header);
    }
    let mut position = 24_u32;
    for segment in 0..prefix[1] {
        let mut header = [0; 8];
        backend
            .read(slot, position, &mut header)
            .map_err(|_| InstalledImageError::Read)?;
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if segment == 0 && length < APP_DESCRIPTOR_PREFIX_SIZE as u32 - APP_DESCRIPTOR_OFFSET {
            return Err(InstalledImageError::Header);
        }
        position = position
            .checked_add(8)
            .and_then(|value| value.checked_add(length))
            .filter(|value| *value <= OTA_SLOT_SIZE - SIGNATURE_SECTOR_SIZE - 48)
            .ok_or(InstalledImageError::Extent)?;
    }
    // ESP images put the checksum at the next 16-byte boundary's last byte,
    // followed by their appended SHA-256. Secure Boot V2 then pads to 4 KiB.
    let trailer_end = (position | 15)
        .checked_add(33)
        .ok_or(InstalledImageError::Extent)?;
    let signature_offset = trailer_end
        .checked_add(SIGNATURE_SECTOR_SIZE - 1)
        .map(|value| value & !(SIGNATURE_SECTOR_SIZE - 1))
        .filter(|value| {
            *value >= SIGNATURE_SECTOR_SIZE && *value <= OTA_SLOT_SIZE - SIGNATURE_SECTOR_SIZE
        })
        .ok_or(InstalledImageError::Extent)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    let mut offset = 0_u32;
    while offset < signature_offset {
        let length = (signature_offset - offset).min(buffer.len() as u32) as usize;
        backend
            .read(slot, offset, &mut buffer[..length])
            .map_err(|_| InstalledImageError::Read)?;
        hasher.update(&buffer[..length]);
        offset += length as u32;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut block = [0; SIGNATURE_BLOCK_SIZE];
    backend
        .read(slot, signature_offset, &mut block)
        .map_err(|_| InstalledImageError::Read)?;
    let signature =
        parse_signature_block(&block, trusted_key_digest).ok_or(InstalledImageError::Signature)?;
    if *signature.image_digest != digest {
        return Err(InstalledImageError::Signature);
    }
    if !backend
        .verify_rsa_pss(signature.public_key, signature.signature, &digest)
        .map_err(|_| InstalledImageError::Signature)?
    {
        return Err(InstalledImageError::Signature);
    }
    Ok(VerifiedInstalledImage {
        secure_version: metadata.secure_version,
        signed_image_bytes: signature_offset + SIGNATURE_SECTOR_SIZE,
        signed_content_digest: digest,
    })
}

pub(crate) struct ImageMetadata<'a> {
    pub(crate) secure_version: u32,
    pub(crate) version: &'a [u8],
}

pub(crate) fn parse_image_metadata(
    image_prefix: &[u8; APP_DESCRIPTOR_PREFIX_SIZE],
) -> Option<ImageMetadata<'_>> {
    if image_prefix[0] != ESP_IMAGE_MAGIC
        || !(1..=16).contains(&image_prefix[1])
        || u16::from_le_bytes(image_prefix[12..14].try_into().ok()?) != ESP32S2_CHIP_ID
        || u32::from_le_bytes(
            image_prefix[APP_DESCRIPTOR_OFFSET as usize..APP_DESCRIPTOR_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        ) != ESP_APP_DESCRIPTOR_MAGIC
    {
        return None;
    }
    let descriptor = &image_prefix[APP_DESCRIPTOR_OFFSET as usize..];
    let secure_version = u32::from_le_bytes(
        descriptor[APP_SECURE_VERSION_OFFSET..APP_SECURE_VERSION_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    let version_field = &descriptor[APP_VERSION_OFFSET..APP_VERSION_OFFSET + 32];
    let version_length = version_field.iter().position(|byte| *byte == 0)?;
    if version_length == 0 || version_length > MAX_VERSION_LENGTH {
        return None;
    }
    Some(ImageMetadata {
        secure_version,
        version: &version_field[..version_length],
    })
}

pub(crate) struct ParsedSignature<'a> {
    pub(crate) image_digest: &'a [u8; 32],
    pub(crate) public_key: &'a [u8; RSA_PUBLIC_KEY_SIZE],
    pub(crate) signature: &'a [u8; RSA_SIGNATURE_SIZE],
}

pub(crate) fn parse_signature_block<'a>(
    block: &'a [u8; SIGNATURE_BLOCK_SIZE],
    trusted_key_digest: &[u8; 32],
) -> Option<ParsedSignature<'a>> {
    if block[0] != SECURE_BOOT_V2_SIGNATURE_MAGIC
        || block[1] != SECURE_BOOT_V2_RSA_VERSION
        || u32::from_le_bytes(block[1196..1200].try_into().ok()?)
            != esp_crc32_le(0, &block[..SIGNATURE_CRC_LENGTH])
    {
        return None;
    }
    let image_digest = block[4..36].try_into().ok()?;
    let public_key = block[36..812].try_into().ok()?;
    let key_digest: [u8; 32] = Sha256::digest(public_key).into();
    if key_digest != *trusted_key_digest {
        return None;
    }
    let signature = block[812..1196].try_into().ok()?;
    Some(ParsedSignature {
        image_digest,
        public_key,
        signature,
    })
}

pub(crate) fn esp_crc32_le(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::{vec, vec::Vec};

    pub(crate) fn signed_image(secure_version: u32, version: &[u8]) -> (Vec<u8>, [u8; 32]) {
        sized_signed_image(
            secure_version,
            version,
            (SIGNATURE_SECTOR_SIZE * 2) as usize,
        )
    }

    pub(crate) fn sized_signed_image(
        secure_version: u32,
        version: &[u8],
        size: usize,
    ) -> (Vec<u8>, [u8; 32]) {
        assert!(size >= (SIGNATURE_SECTOR_SIZE * 2) as usize);
        assert!(size.is_multiple_of(SIGNATURE_SECTOR_SIZE as usize));
        let mut image = vec![0xff; size];
        image[0] = ESP_IMAGE_MAGIC;
        image[1] = 1;
        image[12..14].copy_from_slice(&ESP32S2_CHIP_ID.to_le_bytes());
        image[23] = 1;
        image[32..36].copy_from_slice(&ESP_APP_DESCRIPTOR_MAGIC.to_le_bytes());
        image[36..40].copy_from_slice(&secure_version.to_le_bytes());
        image[48..48 + version.len()].copy_from_slice(version);
        image[48 + version.len()] = 0;

        let signed_length = size - SIGNATURE_SECTOR_SIZE as usize;
        let signed_digest: [u8; 32] = Sha256::digest(&image[..signed_length]).into();
        let block = &mut image[signed_length..signed_length + SIGNATURE_BLOCK_SIZE];
        block[0] = SECURE_BOOT_V2_SIGNATURE_MAGIC;
        block[1] = SECURE_BOOT_V2_RSA_VERSION;
        block[4..36].copy_from_slice(&signed_digest);
        for (index, byte) in block[36..812].iter_mut().enumerate() {
            *byte = index as u8;
        }
        block[812..1196].fill(0x5a);
        let crc = esp_crc32_le(0, &block[..SIGNATURE_CRC_LENGTH]);
        block[1196..1200].copy_from_slice(&crc.to_le_bytes());
        let trusted_digest = Sha256::digest(&block[36..812]).into();
        (image, trusted_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::signed_image;
    use super::*;
    use std::{vec, vec::Vec};

    // Deliberately implements no update/mutation interface.
    struct ReadOnlyBackend {
        slots: [Vec<u8>; 2],
        rsa_valid: bool,
        read_error: bool,
    }

    impl ReadOnlyBackend {
        fn new() -> Self {
            Self {
                slots: [
                    vec![0; OTA_SLOT_SIZE as usize],
                    vec![0; OTA_SLOT_SIZE as usize],
                ],
                rsa_valid: true,
                read_error: false,
            }
        }
    }

    impl ImageReader for ReadOnlyBackend {
        type Error = ();
        fn read(&mut self, slot: u8, offset: u32, output: &mut [u8]) -> Result<(), Self::Error> {
            if self.read_error {
                return Err(());
            }
            let bytes = self
                .slots
                .get(slot as usize)
                .and_then(|s| s.get(offset as usize..offset as usize + output.len()))
                .ok_or(())?;
            output.copy_from_slice(bytes);
            Ok(())
        }
        fn verify_rsa_pss(
            &mut self,
            _key: &[u8; RSA_PUBLIC_KEY_SIZE],
            _signature: &[u8; RSA_SIGNATURE_SIZE],
            _digest: &[u8; 32],
        ) -> Result<bool, Self::Error> {
            Ok(self.rsa_valid)
        }
    }

    fn installed_fixture() -> (ReadOnlyBackend, [u8; 32]) {
        let (mut image, trusted) = signed_image(4, b"normal");
        image[24..28].copy_from_slice(&0x3f00_0020_u32.to_le_bytes());
        image[28..32].copy_from_slice(&256_u32.to_le_bytes());
        let digest = Sha256::digest(&image[..4096]);
        image[4100..4132].copy_from_slice(&digest);
        let crc = esp_crc32_le(0, &image[4096..4096 + SIGNATURE_CRC_LENGTH]);
        image[4096 + 1196..4096 + 1200].copy_from_slice(&crc.to_le_bytes());
        let mut backend = ReadOnlyBackend::new();
        for slot in &mut backend.slots {
            slot[..image.len()].copy_from_slice(&image);
        }
        (backend, trusted)
    }

    #[test]
    fn installed_slot_verification_reads_both_slots_without_mutations() {
        let (mut backend, trusted) = installed_fixture();
        let original = backend.slots.clone();
        for slot in 0..2 {
            let image = verify_installed_slot(&mut backend, slot, &trusted).unwrap();
            assert_eq!(image.secure_version, 4);
            assert_eq!(image.signed_image_bytes, 8192);
            assert_eq!(
                image.signed_content_digest,
                Sha256::digest(&backend.slots[slot as usize][..4096]).as_slice()
            );
        }
        assert_eq!(backend.slots, original);
    }

    #[test]
    fn installed_verifier_handles_qualified_multisegment_image_extents() {
        // Segment lengths from the three epoch-4 test builds. Only layout is
        // retained here: all segment contents and signature bytes are synthetic.
        for (lengths, expected_bytes) in [
            ([7436_u32, 1472, 5120, 51476, 344500], 417792_u32),
            ([7452, 1472, 5120, 51460, 345696], 417792),
            ([7444, 1472, 5120, 51468, 343628], 413696),
        ] {
            let (mut backend, trusted) = installed_fixture();
            let signature = backend.slots[0][4096..4096 + SIGNATURE_BLOCK_SIZE].to_vec();
            backend.slots[0][80..].fill(0);
            backend.slots[0][1] = lengths.len() as u8;
            let mut position = 24_usize;
            for length in lengths {
                backend.slots[0][position + 4..position + 8].copy_from_slice(&length.to_le_bytes());
                position += 8 + length as usize;
            }
            let offset = expected_bytes as usize - SIGNATURE_SECTOR_SIZE as usize;
            let digest = Sha256::digest(&backend.slots[0][..offset]);
            let block = &mut backend.slots[0][offset..offset + SIGNATURE_BLOCK_SIZE];
            block.copy_from_slice(&signature);
            block[4..36].copy_from_slice(&digest);
            let crc = esp_crc32_le(0, &block[..SIGNATURE_CRC_LENGTH]);
            block[1196..1200].copy_from_slice(&crc.to_le_bytes());
            let original = backend.slots.clone();
            let verified = verify_installed_slot(&mut backend, 0, &trusted).unwrap();
            assert_eq!(verified.signed_image_bytes, expected_bytes);
            assert_eq!(verified.signed_content_digest, digest.as_slice());
            assert_eq!(backend.slots, original);
        }
    }

    #[test]
    fn installed_slot_verification_rejects_unbounded_segment_layouts() {
        for length in [u32::MAX, OTA_SLOT_SIZE, OTA_SLOT_SIZE - 4096, 0] {
            let (mut backend, trusted) = installed_fixture();
            backend.slots[0][28..32].copy_from_slice(&length.to_le_bytes());
            let original = backend.slots.clone();
            assert!(matches!(
                verify_installed_slot(&mut backend, 0, &trusted),
                Err(InstalledImageError::Extent | InstalledImageError::Header)
            ));
            assert_eq!(backend.slots, original);
        }
    }

    #[test]
    fn installed_slot_verification_rejects_wrong_root_digest_and_rsa_failure() {
        let (mut backend, mut trusted) = installed_fixture();
        trusted[0] ^= 1;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Signature)
        );
        let (mut backend, trusted) = installed_fixture();
        backend.slots[0][256] ^= 1;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Signature)
        );
        let (mut backend, trusted) = installed_fixture();
        backend.rsa_valid = false;
        let original = backend.slots.clone();
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Signature)
        );
        assert_eq!(backend.slots, original);
    }

    #[test]
    fn installed_slot_verification_rejects_reads_bad_headers_and_invalid_slot() {
        let (mut backend, trusted) = installed_fixture();
        backend.read_error = true;
        assert_eq!(
            verify_installed_slot(&mut backend, 0, &trusted),
            Err(InstalledImageError::Read)
        );
        assert_eq!(
            verify_installed_slot(&mut backend, 2, &trusted),
            Err(InstalledImageError::Slot)
        );
        for (offset, value) in [(0, 0), (1, 0), (1, 17), (23, 0), (36, 17)] {
            let (mut backend, trusted) = installed_fixture();
            backend.slots[0][offset] = value;
            assert_eq!(
                verify_installed_slot(&mut backend, 0, &trusted),
                Err(InstalledImageError::Header)
            );
        }
    }
}
