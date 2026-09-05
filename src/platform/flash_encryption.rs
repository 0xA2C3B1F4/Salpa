//! ESP32-S2 flash-encryption transport used by release builds.
//!
//! Encrypted reads use fixed DROM cache mappings because raw SPI reads return
//! ciphertext. Writes use the ESP32-S2 ROM encryption primitive in 32-byte
//! blocks. This module never enables flash encryption or changes eFuses.

use core::ops::Range;

pub const MMU_PAGE_SIZE: u32 = 0x1_0000;
pub const RESERVED_DROM_START: u32 = 0x3f39_0000;
pub const RESERVED_DROM_END: u32 = 0x3f3f_0000;

const OTADATA_MAPPING: Mapping = Mapping::new(0x3f39_0000, 0x0000_0000, 0x0002_0000);
const OTA0_DESCRIPTOR_MAPPING: Mapping = Mapping::new(0x3f3b_0000, 0x0002_0000, MMU_PAGE_SIZE);
const OTA1_DESCRIPTOR_MAPPING: Mapping = Mapping::new(0x3f3c_0000, 0x0020_0000, MMU_PAGE_SIZE);
pub const FIDO_STORE_MAPPING: Mapping = Mapping::new(0x3f3d_0000, 0x003e_0000, 0x0002_0000);

const MAPPINGS: [Mapping; 4] = [
    OTADATA_MAPPING,
    OTA0_DESCRIPTOR_MAPPING,
    OTA1_DESCRIPTOR_MAPPING,
    FIDO_STORE_MAPPING,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapping {
    pub virtual_start: u32,
    pub physical_start: u32,
    pub size: u32,
}

impl Mapping {
    pub const fn new(virtual_start: u32, physical_start: u32, size: u32) -> Self {
        Self {
            virtual_start,
            physical_start,
            size,
        }
    }

    #[cfg(test)]
    const fn virtual_range(self) -> Range<u32> {
        self.virtual_start..self.virtual_start + self.size
    }

    const fn physical_range(self) -> Range<u32> {
        self.physical_start..self.physical_start + self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashEncryptionError {
    Disabled,
    MappingFailed(i32),
    UnmappedRange,
    NotAligned,
    UnlockFailed(i32),
    EraseFailed(i32),
    WriteFailed(i32),
}

pub fn mapped_virtual_address(address: u32, length: usize) -> Option<u32> {
    let length = u32::try_from(length).ok()?;
    let end = address.checked_add(length)?;
    MAPPINGS.iter().find_map(|mapping| {
        let physical = mapping.physical_range();
        if address >= physical.start && end <= physical.end {
            mapping
                .virtual_start
                .checked_add(address - mapping.physical_start)
        } else {
            None
        }
    })
}

pub const fn encrypted_write_is_aligned(address: u32, length: usize) -> bool {
    address.is_multiple_of(32) && length.is_multiple_of(32)
}

#[cfg(all(
    feature = "release-flash-encryption",
    feature = "mcu-esp32s2",
    not(test)
))]
mod hardware {
    use core::{
        ptr,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::{
        FIDO_STORE_MAPPING, FlashEncryptionError, MAPPINGS, MMU_PAGE_SIZE, OTA0_DESCRIPTOR_MAPPING,
        encrypted_write_is_aligned, mapped_virtual_address,
    };

    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    // ESP32-S2 SOC_MMU_ACCESS_FLASH. Zero does not select external flash.
    // Cache_Ibus_MMU_Set ORs this value into each physical-page entry.
    const MMU_ACCESS_FLASH: u32 = 1 << 15;

    #[repr(align(4))]
    struct EncryptedWriteBlock([u8; 32]);

    unsafe extern "C" {
        #[link_name = "Cache_Ibus_MMU_Set"]
        fn cache_ibus_mmu_set(
            ext_ram: u32,
            virtual_address: u32,
            physical_address: u32,
            page_size_kib: u32,
            page_count: u32,
            fixed: u32,
        ) -> i32;
        #[link_name = "Cache_Disable_ICache"]
        fn cache_disable_icache() -> u32;
        #[link_name = "Cache_Enable_ICache"]
        fn cache_enable_icache(autoload: u32);
        #[link_name = "Cache_Invalidate_Addr"]
        fn cache_invalidate_addr(address: u32, size: u32);
        fn esp_rom_spiflash_write_encrypted(address: u32, data: *mut u32, length: u32) -> i32;
    }

    /// ESP32-S2 DROM is served by IBUS2, even though the CPU reads data.
    /// Scalar arguments are prepared while cache is enabled. This helper and
    /// its ROM callees must execute from RAM/ROM while changing the ICache MMU.
    #[esp_hal::ram]
    fn map_drom(
        _cs: critical_section::CriticalSection<'_>,
        virtual_address: u32,
        physical_address: u32,
        page_count: u32,
    ) -> i32 {
        unsafe {
            // Disable invalidates existing ICache tags. Suspend is not used:
            // the ROM contract forbids ordinary MMU changes while suspended.
            let autoload = cache_disable_icache();
            let result = cache_ibus_mmu_set(
                MMU_ACCESS_FLASH,
                virtual_address,
                physical_address,
                MMU_PAGE_SIZE / 1024,
                page_count,
                0,
            );
            // Restore cache operation on success and failure alike.
            cache_enable_icache(autoload);
            result
        }
    }

    fn map_release_regions(
        cs: critical_section::CriticalSection<'_>,
    ) -> Result<(), FlashEncryptionError> {
        for mapping in MAPPINGS {
            let result = map_drom(
                cs,
                mapping.virtual_start,
                mapping.physical_start,
                mapping.size / MMU_PAGE_SIZE,
            );
            if result != 0 {
                return Err(FlashEncryptionError::MappingFailed(result));
            }
        }
        Ok(())
    }

    pub fn initialize() -> Result<(), FlashEncryptionError> {
        if !esp_hal::efuse::flash_encryption() {
            return Err(FlashEncryptionError::Disabled);
        }
        if INITIALIZED.load(Ordering::Acquire) {
            return Ok(());
        }
        critical_section::with(map_release_regions)?;
        INITIALIZED.store(true, Ordering::Release);
        Ok(())
    }

    pub fn read(address: u32, output: &mut [u8]) -> Result<(), FlashEncryptionError> {
        if !INITIALIZED.load(Ordering::Acquire) {
            return Err(FlashEncryptionError::Disabled);
        }
        let virtual_address = mapped_virtual_address(address, output.len())
            .ok_or(FlashEncryptionError::UnmappedRange)?;
        unsafe {
            ptr::copy_nonoverlapping(
                virtual_address as *const u8,
                output.as_mut_ptr(),
                output.len(),
            );
        }
        Ok(())
    }

    #[esp_hal::ram]
    fn map_update_page_and_copy(
        physical_page: u32,
        page_offset: u32,
        output: &mut [u8],
    ) -> Result<(), FlashEncryptionError> {
        critical_section::with(|cs| {
            let mapped = map_drom(cs, OTA0_DESCRIPTOR_MAPPING.virtual_start, physical_page, 1);
            if mapped != 0 {
                return Err(FlashEncryptionError::MappingFailed(mapped));
            }
            unsafe {
                cache_invalidate_addr(OTA0_DESCRIPTOR_MAPPING.virtual_start, MMU_PAGE_SIZE);
                ptr::copy_nonoverlapping(
                    (OTA0_DESCRIPTOR_MAPPING.virtual_start + page_offset) as *const u8,
                    output.as_mut_ptr(),
                    output.len(),
                );
            }
            let restored = map_drom(
                cs,
                OTA0_DESCRIPTOR_MAPPING.virtual_start,
                OTA0_DESCRIPTOR_MAPPING.physical_start,
                1,
            );
            unsafe {
                cache_invalidate_addr(OTA0_DESCRIPTOR_MAPPING.virtual_start, MMU_PAGE_SIZE);
            }
            if restored != 0 {
                return Err(FlashEncryptionError::MappingFailed(restored));
            }
            Ok(())
        })
    }

    /// Read arbitrary encrypted OTA bytes through one temporary DROM page.
    /// The fixed descriptor mapping is restored before returning.
    pub fn read_update(
        mut address: u32,
        mut output: &mut [u8],
    ) -> Result<(), FlashEncryptionError> {
        if !INITIALIZED.load(Ordering::Acquire) {
            return Err(FlashEncryptionError::Disabled);
        }
        address
            .checked_add(
                u32::try_from(output.len()).map_err(|_| FlashEncryptionError::UnmappedRange)?,
            )
            .ok_or(FlashEncryptionError::UnmappedRange)?;
        while !output.is_empty() {
            let physical_page = address & !(MMU_PAGE_SIZE - 1);
            let page_offset = address - physical_page;
            let count = output.len().min((MMU_PAGE_SIZE - page_offset) as usize);
            let (current, rest) = output.split_at_mut(count);
            map_update_page_and_copy(physical_page, page_offset, current)?;
            address += count as u32;
            output = rest;
        }
        Ok(())
    }

    #[esp_hal::ram]
    fn write_block(address: u32, block: &mut EncryptedWriteBlock) -> i32 {
        critical_section::with(|_| unsafe {
            esp_rom_spiflash_write_encrypted(address, block.0.as_mut_ptr().cast(), 32)
        })
    }

    #[esp_hal::ram]
    fn invalidate(address: u32, size: u32) {
        critical_section::with(|_| unsafe { cache_invalidate_addr(address, size) });
    }

    fn invalidate_physical_range(
        physical_address: u32,
        length: usize,
    ) -> Result<(), FlashEncryptionError> {
        let virtual_address = mapped_virtual_address(physical_address, length)
            .ok_or(FlashEncryptionError::UnmappedRange)?;
        let size = u32::try_from(length).map_err(|_| FlashEncryptionError::UnmappedRange)?;
        invalidate(virtual_address, size);
        Ok(())
    }

    pub fn write(address: u32, data: &[u8]) -> Result<(), FlashEncryptionError> {
        write_inner(address, data, true)
    }

    fn write_inner(
        address: u32,
        data: &[u8],
        invalidate_fixed_mapping: bool,
    ) -> Result<(), FlashEncryptionError> {
        if !INITIALIZED.load(Ordering::Acquire) {
            return Err(FlashEncryptionError::Disabled);
        }
        if !encrypted_write_is_aligned(address, data.len()) {
            return Err(FlashEncryptionError::NotAligned);
        }
        unsafe { esp_storage::ll::spiflash_unlock() }
            .map_err(FlashEncryptionError::UnlockFailed)?;
        for (index, chunk) in data.chunks_exact(32).enumerate() {
            let mut block = EncryptedWriteBlock([0; 32]);
            block.0.copy_from_slice(chunk);
            let result = write_block(address + (index as u32 * 32), &mut block);
            block.0.fill(0);
            if result != 0 {
                return Err(FlashEncryptionError::WriteFailed(result));
            }
        }
        if invalidate_fixed_mapping {
            invalidate_physical_range(address, data.len())?;
        }
        Ok(())
    }

    /// Encrypt plaintext with the device flash key while writing an OTA slot.
    pub fn write_update(address: u32, data: &[u8]) -> Result<(), FlashEncryptionError> {
        write_inner(address, data, false)
    }

    pub fn erase(address: u32, length: usize) -> Result<(), FlashEncryptionError> {
        erase_inner(address, length, true)
    }

    fn erase_inner(
        address: u32,
        length: usize,
        invalidate_fixed_mapping: bool,
    ) -> Result<(), FlashEncryptionError> {
        if !INITIALIZED.load(Ordering::Acquire) {
            return Err(FlashEncryptionError::Disabled);
        }
        if !address.is_multiple_of(0x1000) || !length.is_multiple_of(0x1000) {
            return Err(FlashEncryptionError::NotAligned);
        }
        unsafe { esp_storage::ll::spiflash_unlock() }
            .map_err(FlashEncryptionError::UnlockFailed)?;
        let end = address
            .checked_add(u32::try_from(length).map_err(|_| FlashEncryptionError::UnmappedRange)?)
            .ok_or(FlashEncryptionError::UnmappedRange)?;
        for sector_address in (address..end).step_by(0x1000) {
            unsafe { esp_storage::ll::spiflash_erase_sector(sector_address / 0x1000) }
                .map_err(FlashEncryptionError::EraseFailed)?;
        }
        if invalidate_fixed_mapping {
            invalidate_physical_range(address, length)?;
        }
        Ok(())
    }

    pub fn erase_update(address: u32, length: usize) -> Result<(), FlashEncryptionError> {
        erase_inner(address, length, false)
    }

    const _: () = {
        assert!(FIDO_STORE_MAPPING.physical_start == 0x3e_0000);
        assert!(FIDO_STORE_MAPPING.size == 0x2_0000);
    };
}

#[cfg(all(
    feature = "release-flash-encryption",
    feature = "mcu-esp32s2",
    not(test)
))]
pub use hardware::{erase, erase_update, initialize, read, read_update, write, write_update};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_are_page_aligned_and_disjoint() {
        for (index, mapping) in MAPPINGS.iter().enumerate() {
            assert!(mapping.virtual_start.is_multiple_of(MMU_PAGE_SIZE));
            assert!(mapping.physical_start.is_multiple_of(MMU_PAGE_SIZE));
            assert!(mapping.size.is_multiple_of(MMU_PAGE_SIZE));
            assert!(mapping.virtual_range().start >= RESERVED_DROM_START);
            assert!(mapping.virtual_range().end <= RESERVED_DROM_END);
            for other in &MAPPINGS[index + 1..] {
                assert!(mapping.virtual_range().end <= other.virtual_range().start);
            }
        }
    }

    #[test]
    fn mappings_cover_release_reads() {
        assert_eq!(mapped_virtual_address(0x0000_f000, 32), Some(0x3f39_f000));
        assert_eq!(mapped_virtual_address(0x0001_0000, 32), Some(0x3f3a_0000));
        assert_eq!(mapped_virtual_address(0x0002_0020, 256), Some(0x3f3b_0020));
        assert_eq!(mapped_virtual_address(0x0020_0020, 256), Some(0x3f3c_0020));
        assert_eq!(
            mapped_virtual_address(0x003e_0000, 0x2_0000),
            Some(0x3f3d_0000)
        );
        assert_eq!(mapped_virtual_address(0x003d_ffff, 2), None);
        assert_eq!(mapped_virtual_address(0x003f_ffff, 2), None);
    }

    #[test]
    fn encrypted_writes_require_rom_block_alignment() {
        assert!(encrypted_write_is_aligned(0x3e_0000, 32));
        assert!(encrypted_write_is_aligned(0x3e_0020, 64));
        assert!(!encrypted_write_is_aligned(0x3e_0004, 32));
        assert!(!encrypted_write_is_aligned(0x3e_0000, 16));
    }
}
