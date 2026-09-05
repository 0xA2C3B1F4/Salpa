//! littlefs2 storage types for Trussed.
//!
//! Normal firmware may mount `FidoFlashStorage`, but must never format it after
//! a mount error. Formatting is reserved for a separate provisioning or
//! factory-reset path.

#[cfg(not(feature = "release-flash-encryption"))]
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
#[cfg(not(feature = "release-flash-encryption"))]
use esp_storage::FlashStorage;
use littlefs2::{
    const_ram_storage,
    consts::{U1, U256},
    driver::Storage,
    io::{Error, Result},
    object_safe::DynFilesystem,
};
use trussed::store::Store as TrussedStore;

use super::storage_layout::{ERASE_SIZE, FIDO_STORE_BLOCK_COUNT, checked_absolute_range};

pub use super::storage_init::{
    MountExistingError, PERSISTENT_STATE_INITIALIZATION_MARKER, STORAGE_FORMAT_VERSION,
    StorageVersionError, mount_existing, verify_storage_version,
    write_persistent_state_initialization_marker, write_storage_version,
};

// Keep the provisioning image and the authenticator fork on one marker
// contract without making the storage-only host tests compile the FIDO stack.
const _: () = {
    let platform = PERSISTENT_STATE_INITIALIZATION_MARKER;
    let authenticator = fido_authenticator::state::PersistentState::INITIALIZATION_MARKER;
    assert!(platform.len() == authenticator.len());
    let mut index = 0;
    while index < platform.len() {
        assert!(platform[index] == authenticator[index]);
        index += 1;
    }
};

pub const VOLATILE_STORE_SIZE: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackendError {
    FlashEncryption,
}

/// Restricts all littlefs2 operations to the `fido_store` partition.
pub struct FidoFlashStorage {
    #[cfg(not(feature = "release-flash-encryption"))]
    flash: FlashStorage<'static>,
    #[cfg(feature = "release-flash-encryption")]
    _flash: esp_hal::peripherals::FLASH<'static>,
}

impl FidoFlashStorage {
    pub fn new(
        flash: esp_hal::peripherals::FLASH<'static>,
    ) -> core::result::Result<Self, StorageBackendError> {
        #[cfg(not(feature = "release-flash-encryption"))]
        return Ok(Self {
            flash: FlashStorage::new(flash),
        });

        #[cfg(feature = "release-flash-encryption")]
        {
            super::flash_encryption::initialize()
                .map_err(|_| StorageBackendError::FlashEncryption)?;
            Ok(Self { _flash: flash })
        }
    }

    fn absolute_range(offset: usize, len: usize) -> Result<(u32, u32)> {
        checked_absolute_range(offset, len).ok_or(Error::IO)
    }
}

impl Storage for FidoFlashStorage {
    const READ_SIZE: usize = 4;
    #[cfg(not(feature = "release-flash-encryption"))]
    const WRITE_SIZE: usize = 4;
    #[cfg(feature = "release-flash-encryption")]
    const WRITE_SIZE: usize = 32;
    const BLOCK_SIZE: usize = ERASE_SIZE;
    const BLOCK_COUNT: usize = FIDO_STORE_BLOCK_COUNT;
    const BLOCK_CYCLES: isize = 500;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U1;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<usize> {
        let (start, _) = Self::absolute_range(offset, buffer.len())?;
        #[cfg(not(feature = "release-flash-encryption"))]
        ReadNorFlash::read(&mut self.flash, start, buffer).map_err(|_| Error::IO)?;
        #[cfg(feature = "release-flash-encryption")]
        super::flash_encryption::read(start, buffer).map_err(|_| Error::IO)?;
        Ok(buffer.len())
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        let (start, _) = Self::absolute_range(offset, data.len())?;
        #[cfg(not(feature = "release-flash-encryption"))]
        NorFlash::write(&mut self.flash, start, data).map_err(|_| Error::IO)?;
        #[cfg(feature = "release-flash-encryption")]
        super::flash_encryption::write(start, data).map_err(|_| Error::IO)?;
        Ok(data.len())
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<usize> {
        let (start, _end) = Self::absolute_range(offset, len)?;
        #[cfg(not(feature = "release-flash-encryption"))]
        NorFlash::erase(&mut self.flash, start, _end).map_err(|_| Error::IO)?;
        #[cfg(feature = "release-flash-encryption")]
        super::flash_encryption::erase(start, len).map_err(|_| Error::IO)?;
        Ok(len)
    }
}

const_ram_storage!(VolatileStorage, VOLATILE_STORE_SIZE);

/// Filesystem references exposed to Trussed.
///
/// This board has no separate external credential medium, so `External`
/// aliases the persistent internal filesystem. `Volatile` always has its own
/// RAM-backed filesystem.
#[derive(Clone, Copy)]
pub struct FilesystemSet<'a> {
    internal: &'a dyn DynFilesystem,
    volatile: &'a dyn DynFilesystem,
}

impl<'a> FilesystemSet<'a> {
    pub const fn new(internal: &'a dyn DynFilesystem, volatile: &'a dyn DynFilesystem) -> Self {
        Self { internal, volatile }
    }
}

impl TrussedStore for FilesystemSet<'_> {
    fn ifs(&self) -> &dyn DynFilesystem {
        self.internal
    }

    fn efs(&self) -> &dyn DynFilesystem {
        self.internal
    }

    fn vfs(&self) -> &dyn DynFilesystem {
        self.volatile
    }
}
