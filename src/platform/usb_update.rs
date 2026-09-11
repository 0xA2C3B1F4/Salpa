//! ESP32-S2 storage and ROM-signature backend for USB signed updates.
//!
//! Plain development builds use raw SPI operations. Protected builds feed
//! plaintext to the ESP32-S2 encrypted-write ROM primitive, so the inactive
//! slot is encrypted with the device key as it is written.

use crate::{
    platform::ota,
    usb_update::{
        OTA_SLOT_SIZE, RSA_PUBLIC_KEY_SIZE, RSA_SIGNATURE_SIZE, UpdateBackend, UpdateLayout,
    },
};

const FLASH_SECTOR_SIZE: u32 = 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Address,
    Flash,
    Ota,
}

pub struct Esp32S2UpdateBackend {
    descriptor_address: u32,
}

impl Esp32S2UpdateBackend {
    pub const fn new(descriptor_address: u32) -> Self {
        Self { descriptor_address }
    }

    fn address(slot: u8, offset: u32, length: usize) -> Result<u32, Error> {
        let base = ota::update_slot_offset(slot).ok_or(Error::Address)?;
        let length = u32::try_from(length).map_err(|_| Error::Address)?;
        let end = offset.checked_add(length).ok_or(Error::Address)?;
        if end > OTA_SLOT_SIZE {
            return Err(Error::Address);
        }
        base.checked_add(offset).ok_or(Error::Address)
    }
}

impl UpdateBackend for Esp32S2UpdateBackend {
    type Error = Error;

    fn now_ms(&self) -> u64 {
        esp_hal::time::Instant::now()
            .duration_since_epoch()
            .as_millis()
    }

    fn layout(&mut self) -> Result<UpdateLayout, Self::Error> {
        ota::update_layout(self.descriptor_address).map_err(|_| Error::Ota)
    }

    fn erase(&mut self, slot: u8, offset: u32, length: u32) -> Result<(), Self::Error> {
        if !offset.is_multiple_of(FLASH_SECTOR_SIZE)
            || !length.is_multiple_of(FLASH_SECTOR_SIZE)
            || length == 0
        {
            return Err(Error::Address);
        }
        let address = Self::address(slot, offset, length as usize)?;
        #[cfg(feature = "release-flash-encryption")]
        {
            super::flash_encryption::erase_update(address, length as usize)
                .map_err(|_| Error::Flash)
        }
        #[cfg(not(feature = "release-flash-encryption"))]
        {
            unsafe { esp_storage::ll::spiflash_unlock() }.map_err(|_| Error::Flash)?;
            let end = address.checked_add(length).ok_or(Error::Address)?;
            for sector in (address..end).step_by(FLASH_SECTOR_SIZE as usize) {
                unsafe { esp_storage::ll::spiflash_erase_sector(sector / FLASH_SECTOR_SIZE) }
                    .map_err(|_| Error::Flash)?;
            }
            Ok(())
        }
    }

    fn write(&mut self, slot: u8, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        if data.is_empty() || !offset.is_multiple_of(32) || !data.len().is_multiple_of(32) {
            return Err(Error::Address);
        }
        let address = Self::address(slot, offset, data.len())?;
        #[cfg(feature = "release-flash-encryption")]
        {
            super::flash_encryption::write_update(address, data).map_err(|_| Error::Flash)
        }
        #[cfg(not(feature = "release-flash-encryption"))]
        {
            #[repr(align(4))]
            struct Aligned([u8; crate::usb_update::MAX_WRITE_CHUNK]);

            let mut aligned = Aligned([0; crate::usb_update::MAX_WRITE_CHUNK]);
            aligned.0[..data.len()].copy_from_slice(data);
            unsafe { esp_storage::ll::spiflash_unlock() }.map_err(|_| Error::Flash)?;
            unsafe {
                esp_storage::ll::spiflash_write(
                    address,
                    aligned.0.as_ptr().cast(),
                    data.len() as u32,
                )
            }
            .map_err(|_| Error::Flash)?;
            aligned.0.fill(0);
            Ok(())
        }
    }

    fn read(&mut self, slot: u8, offset: u32, output: &mut [u8]) -> Result<(), Self::Error> {
        let address = Self::address(slot, offset, output.len())?;
        #[cfg(feature = "release-flash-encryption")]
        {
            super::flash_encryption::read_update(address, output).map_err(|_| Error::Flash)
        }
        #[cfg(not(feature = "release-flash-encryption"))]
        {
            #[repr(align(4))]
            struct Aligned([u8; 1024]);

            let mut aligned = Aligned([0; 1024]);
            let mut remaining = output;
            let mut address = address;
            while !remaining.is_empty() {
                let count = remaining.len().min(aligned.0.len());
                unsafe {
                    esp_storage::ll::spiflash_read(
                        address,
                        aligned.0.as_mut_ptr().cast(),
                        count as u32,
                    )
                }
                .map_err(|_| Error::Flash)?;
                remaining[..count].copy_from_slice(&aligned.0[..count]);
                remaining = &mut remaining[count..];
                address += count as u32;
            }
            aligned.0.fill(0);
            Ok(())
        }
    }

    fn verify_rsa_pss(
        &mut self,
        public_key: &[u8; RSA_PUBLIC_KEY_SIZE],
        signature: &[u8; RSA_SIGNATURE_SIZE],
        image_digest: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        #[repr(C, align(4))]
        struct RsaPublicKey {
            modulus: [u8; 384],
            exponent: u32,
            rinv: [u8; 384],
            mdash: u32,
        }

        #[repr(align(4))]
        struct AlignedDigest([u8; 32]);

        #[repr(align(4))]
        struct AlignedSignature([u8; RSA_SIGNATURE_SIZE]);

        unsafe extern "C" {
            fn ets_rsa_pss_verify(
                key: *const RsaPublicKey,
                signature: *const u8,
                digest: *const u8,
                verified_digest: *mut u8,
            ) -> bool;
        }

        let mut key = RsaPublicKey {
            modulus: [0; 384],
            exponent: u32::from_le_bytes(public_key[384..388].try_into().unwrap()),
            rinv: [0; 384],
            mdash: u32::from_le_bytes(public_key[772..776].try_into().unwrap()),
        };
        key.modulus.copy_from_slice(&public_key[..384]);
        key.rinv.copy_from_slice(&public_key[388..772]);
        let mut signature = AlignedSignature(*signature);
        let digest = AlignedDigest(*image_digest);
        let mut verified = AlignedDigest([0; 32]);
        let valid = unsafe {
            ets_rsa_pss_verify(
                &key,
                signature.0.as_ptr(),
                digest.0.as_ptr(),
                verified.0.as_mut_ptr(),
            )
        };
        let matches = valid && verified.0 == *image_digest;
        signature.0.fill(0);
        verified.0.fill(0);
        Ok(matches)
    }

    fn activate(
        &mut self,
        slot: u8,
        sequence: u32,
        activation_entry: u8,
    ) -> Result<(), Self::Error> {
        ota::activate_update(slot, sequence, activation_entry, self.descriptor_address)
            .map_err(|_| Error::Ota)
    }
}

pub const fn trusted_update_key_digest() -> [u8; 32] {
    const HEX: &str = env!("SALPA_UPDATE_KEY_DIGEST_HEX");
    let bytes = HEX.as_bytes();
    assert!(bytes.len() == 64);
    let mut output = [0; 32];
    let mut index = 0;
    while index < output.len() {
        output[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("trusted update-key digest must be lowercase hexadecimal"),
    }
}
