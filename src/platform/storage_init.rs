//! Normal-firmware mounting and version checks for persistent FIDO storage.
//!
//! This module deliberately exposes no formatting operation.  Keeping the
//! normal startup path here makes its fail-closed policy usable by host tests.

use littlefs2::{
    driver::Storage,
    fs::{Allocation, Filesystem},
    io::Error,
};

pub const STORAGE_FORMAT_VERSION: &[u8] = b"rissokey-fido-store-v1\n";

pub const PERSISTENT_STATE_INITIALIZATION_MARKER: &[u8] = b"rissokey-persistent-state-init-v1\n";

const STORAGE_FORMAT_VERSION_PATH: &littlefs2::path::Path =
    littlefs2::path!("/.rissokey-storage-format");
const PERSISTENT_STATE_INITIALIZATION_MARKER_PATH: &littlefs2::path::Path =
    littlefs2::path!("/fido/dat/persistent-state.init");

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StorageVersionError {
    Filesystem(Error),
    VersionMismatch,
}

impl From<Error> for StorageVersionError {
    fn from(error: Error) -> Self {
        Self::Filesystem(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MountExistingError {
    Mount(Error),
    Version(StorageVersionError),
}

impl From<StorageVersionError> for MountExistingError {
    fn from(error: StorageVersionError) -> Self {
        Self::Version(error)
    }
}

pub fn write_storage_version<S: Storage>(
    filesystem: &Filesystem<'_, S>,
) -> core::result::Result<(), StorageVersionError> {
    filesystem.write(STORAGE_FORMAT_VERSION_PATH, STORAGE_FORMAT_VERSION)?;
    verify_storage_version(filesystem)
}

/// Authorizes one first initialization of the FIDO persistent state.
///
/// Only a destructive provisioning image may call this function. Normal
/// firmware consumes the marker after it has saved a valid initial state.
pub fn write_persistent_state_initialization_marker<S: Storage>(
    filesystem: &Filesystem<'_, S>,
) -> core::result::Result<(), Error> {
    filesystem.create_dir_all(littlefs2::path!("/fido/dat"))?;
    filesystem.write(
        PERSISTENT_STATE_INITIALIZATION_MARKER_PATH,
        PERSISTENT_STATE_INITIALIZATION_MARKER,
    )?;
    let stored = filesystem.read::<64>(PERSISTENT_STATE_INITIALIZATION_MARKER_PATH)?;
    if stored.as_slice() == PERSISTENT_STATE_INITIALIZATION_MARKER {
        Ok(())
    } else {
        Err(Error::CORRUPTION)
    }
}

pub fn verify_storage_version<S: Storage>(
    filesystem: &Filesystem<'_, S>,
) -> core::result::Result<(), StorageVersionError> {
    let stored = filesystem.read::<32>(STORAGE_FORMAT_VERSION_PATH)?;
    if stored.as_slice() == STORAGE_FORMAT_VERSION {
        Ok(())
    } else {
        Err(StorageVersionError::VersionMismatch)
    }
}

/// Mounts a previously provisioned FIDO store and validates its format marker.
///
/// Normal firmware uses this function instead of littlefs2's `mount_or_else`.
/// A mount or version failure is returned to the caller without modifying the
/// storage device.
pub fn mount_existing<'a, S: Storage>(
    allocation: &'a mut Allocation<S>,
    storage: &'a mut S,
) -> core::result::Result<Filesystem<'a, S>, MountExistingError> {
    let filesystem = Filesystem::mount(allocation, storage).map_err(MountExistingError::Mount)?;
    verify_storage_version(&filesystem)?;
    Ok(filesystem)
}

/// Accept only the exact storage-only provisioner's fresh tree. No writes.
pub fn verify_empty_identity_import_target<S: Storage>(
    filesystem: &Filesystem<'_, S>,
) -> core::result::Result<(), Error> {
    fn directory<S: Storage>(
        fs: &Filesystem<'_, S>,
        path: &littlefs2::path::Path,
        allowed: &[&littlefs2::path::Path],
    ) -> core::result::Result<(), Error> {
        fs.read_dir_and_then(path, |entries| {
            let mut count = 0;
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                if name == littlefs2::path!(".") || name == littlefs2::path!("..") {
                    continue;
                }
                if !allowed.contains(&name) {
                    return Err(Error::DIR_NOT_EMPTY);
                }
                count += 1;
            }
            if count == allowed.len() {
                Ok(())
            } else {
                Err(Error::DIR_NOT_EMPTY)
            }
        })
    }
    directory(
        filesystem,
        littlefs2::path!("/"),
        &[
            littlefs2::path!(".rissokey-storage-format"),
            littlefs2::path!("fido"),
        ],
    )?;
    directory(
        filesystem,
        littlefs2::path!("/fido"),
        &[littlefs2::path!("dat")],
    )?;
    directory(
        filesystem,
        littlefs2::path!("/fido/dat"),
        &[littlefs2::path!("persistent-state.init")],
    )?;
    let marker = filesystem.read::<64>(PERSISTENT_STATE_INITIALIZATION_MARKER_PATH)?;
    if marker.as_slice() == PERSISTENT_STATE_INITIALIZATION_MARKER {
        Ok(())
    } else {
        Err(Error::CORRUPTION)
    }
}
