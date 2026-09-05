#[cfg(test)]
#[path = "../../../src/platform/storage_init.rs"]
mod storage_init;

#[cfg(test)]
mod tests {
    use littlefs2::{
        consts::{U1, U256},
        driver::Storage,
        fs::{Allocation, Filesystem},
        io::{Error, Result},
        path,
    };

    use super::storage_init;

    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = 32;
    const STORE_SIZE: usize = BLOCK_SIZE * BLOCK_COUNT;

    const RECORD_PATH: &littlefs2::path::Path = path!("/fido/sec/test-record");
    const OLD_RECORD: &[u8] = b"credential-record-before-interruption";
    const NEW_RECORD: &[u8] = b"credential-record-after-interruption";

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum MutationKind {
        Write,
        Erase,
    }

    #[derive(Clone, Copy, Debug)]
    struct FaultPlan {
        mutation: usize,
        prefix_bytes: usize,
    }

    struct FaultStorage {
        bytes: Vec<u8>,
        mutations: Vec<(MutationKind, usize)>,
        reads: usize,
        writes: usize,
        erases: usize,
        fail_read: Option<usize>,
        plan: Option<FaultPlan>,
        failed: bool,
    }

    impl FaultStorage {
        fn erased() -> Self {
            Self::from_bytes(vec![0xff; STORE_SIZE])
        }

        fn from_bytes(bytes: Vec<u8>) -> Self {
            assert_eq!(bytes.len(), STORE_SIZE);
            Self {
                bytes,
                mutations: Vec::new(),
                reads: 0,
                writes: 0,
                erases: 0,
                fail_read: None,
                plan: None,
                failed: false,
            }
        }

        fn snapshot(&self) -> Vec<u8> {
            self.bytes.clone()
        }

        fn with_fault(bytes: Vec<u8>, plan: FaultPlan) -> Self {
            let mut storage = Self::from_bytes(bytes);
            storage.plan = Some(plan);
            storage
        }

        fn with_read_fault(bytes: Vec<u8>, read: usize) -> Self {
            let mut storage = Self::from_bytes(bytes);
            storage.fail_read = Some(read);
            storage
        }

        fn mutation_prefix(&mut self, kind: MutationKind, len: usize) -> Option<usize> {
            let index = self.mutations.len();
            self.mutations.push((kind, len));
            match self.plan {
                Some(plan) if plan.mutation == index => {
                    self.failed = true;
                    Some(plan.prefix_bytes.min(len))
                }
                _ => None,
            }
        }

        fn reject_if_failed(&self) -> Result<()> {
            if self.failed { Err(Error::IO) } else { Ok(()) }
        }

        fn program(&mut self, offset: usize, data: &[u8]) {
            for (current, requested) in self.bytes[offset..].iter_mut().zip(data) {
                *current &= *requested;
            }
        }

        fn corrupt(&mut self, offset: usize, len: usize, value: u8) {
            self.bytes[offset..offset + len].fill(value);
        }
    }

    impl Storage for FaultStorage {
        const READ_SIZE: usize = 4;
        const WRITE_SIZE: usize = 4;
        const BLOCK_SIZE: usize = BLOCK_SIZE;
        const BLOCK_COUNT: usize = BLOCK_COUNT;
        const BLOCK_CYCLES: isize = 500;

        type CACHE_SIZE = U256;
        type LOOKAHEAD_SIZE = U1;

        fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<usize> {
            self.reject_if_failed()?;
            let read = self.reads;
            self.reads += 1;
            if self.fail_read == Some(read) {
                self.failed = true;
                return Err(Error::IO);
            }
            buffer.copy_from_slice(&self.bytes[offset..offset + buffer.len()]);
            Ok(buffer.len())
        }

        fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
            self.reject_if_failed()?;
            self.writes += 1;
            if let Some(prefix) = self.mutation_prefix(MutationKind::Write, data.len()) {
                self.program(offset, &data[..prefix]);
                return Err(Error::IO);
            }
            self.program(offset, data);
            Ok(data.len())
        }

        fn erase(&mut self, offset: usize, len: usize) -> Result<usize> {
            self.reject_if_failed()?;
            self.erases += 1;
            if let Some(prefix) = self.mutation_prefix(MutationKind::Erase, len) {
                self.bytes[offset..offset + prefix].fill(0xff);
                return Err(Error::IO);
            }
            self.bytes[offset..offset + len].fill(0xff);
            Ok(len)
        }
    }

    fn provisioned_image() -> Vec<u8> {
        let mut storage = FaultStorage::from_bytes(formatted_image());
        Filesystem::mount_and_then(&mut storage, |filesystem| {
            storage_init::write_storage_version(filesystem).unwrap();
            storage_init::write_persistent_state_initialization_marker(filesystem).unwrap();
            filesystem.create_dir_all(path!("/fido/sec"))?;
            filesystem.write(RECORD_PATH, OLD_RECORD)
        })
        .unwrap();
        storage.snapshot()
    }

    fn formatted_image() -> Vec<u8> {
        let mut storage = FaultStorage::erased();
        Filesystem::format(&mut storage).unwrap();
        storage.snapshot()
    }

    fn read_record(storage: &mut FaultStorage) -> core::result::Result<Vec<u8>, String> {
        let mut allocation = Allocation::new();
        let filesystem = storage_init::mount_existing(&mut allocation, storage)
            .map_err(|error| format!("mount failed after interruption: {error:?}"))?;
        let record = filesystem
            .read::<64>(RECORD_PATH)
            .map_err(|error| format!("record read failed after interruption: {error:?}"))?;
        Ok(record.as_slice().to_vec())
    }

    fn image_before_erase() -> (Vec<u8>, &'static [u8]) {
        let mut storage = FaultStorage::from_bytes(provisioned_image());
        for index in 0..2_000 {
            let before = storage.snapshot();
            storage.mutations.clear();
            storage.writes = 0;
            storage.erases = 0;
            let record = if index % 2 == 0 {
                NEW_RECORD
            } else {
                OLD_RECORD
            };
            Filesystem::mount_and_then(&mut storage, |filesystem| {
                filesystem.write(RECORD_PATH, record)
            })
            .unwrap();
            if storage.erases > 0 {
                return (before, record);
            }
        }
        panic!("rewrite preparation did not reach a flash erase")
    }

    #[test]
    fn normal_mount_and_version_check_are_read_only() {
        let image = provisioned_image();
        let mut storage = FaultStorage::from_bytes(image.clone());
        assert_eq!(read_record(&mut storage).unwrap(), OLD_RECORD);
        assert_eq!(storage.bytes, image);
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.erases, 0);
    }

    #[test]
    fn identity_import_accepts_only_initialization_markers_without_writes() {
        let mut storage = FaultStorage::from_bytes(formatted_image());
        Filesystem::mount_and_then(&mut storage, |fs| {
            storage_init::write_storage_version(fs).unwrap();
            storage_init::write_persistent_state_initialization_marker(fs)
        })
        .unwrap();
        let snapshot = storage.snapshot();
        storage.writes = 0;
        storage.erases = 0;
        Filesystem::mount_and_then(
            &mut storage,
            storage_init::verify_empty_identity_import_target,
        )
        .unwrap();
        assert_eq!(storage.bytes, snapshot);
        assert_eq!((storage.writes, storage.erases), (0, 0));
    }

    #[test]
    fn identity_import_rejects_existing_records_without_modifying_them() {
        let mut storage = FaultStorage::from_bytes(provisioned_image());
        let snapshot = storage.snapshot();
        storage.writes = 0;
        storage.erases = 0;
        assert!(
            Filesystem::mount_and_then(
                &mut storage,
                storage_init::verify_empty_identity_import_target
            )
            .is_err()
        );
        assert_eq!(storage.bytes, snapshot);
        assert_eq!((storage.writes, storage.erases), (0, 0));
    }

    #[test]
    fn identity_import_rejects_corrupt_initialization_marker() {
        let mut storage = FaultStorage::from_bytes(formatted_image());
        Filesystem::mount_and_then(&mut storage, |fs| {
            storage_init::write_storage_version(fs).unwrap();
            storage_init::write_persistent_state_initialization_marker(fs)?;
            fs.write(path!("/fido/dat/persistent-state.init"), b"corrupt")
        })
        .unwrap();
        let snapshot = storage.snapshot();
        assert!(
            Filesystem::mount_and_then(
                &mut storage,
                storage_init::verify_empty_identity_import_target
            )
            .is_err()
        );
        assert_eq!(storage.bytes, snapshot);
    }

    #[test]
    fn corrupt_or_missing_filesystem_is_rejected_without_mutation() {
        for image in [vec![0xff; STORE_SIZE], vec![0x00; STORE_SIZE]] {
            let original = image.clone();
            let mut storage = FaultStorage::from_bytes(image);
            let mut allocation = Allocation::new();
            assert!(storage_init::mount_existing(&mut allocation, &mut storage).is_err());
            assert_eq!(storage.bytes, original);
            assert_eq!(storage.writes, 0);
            assert_eq!(storage.erases, 0);
        }
    }

    #[test]
    fn every_startup_read_failure_is_returned_without_mutation() {
        let image = provisioned_image();
        let mut successful = FaultStorage::from_bytes(image.clone());
        {
            let mut allocation = Allocation::new();
            storage_init::mount_existing(&mut allocation, &mut successful).unwrap();
        }
        assert!(successful.reads > 0);

        for read in 0..successful.reads {
            let mut storage = FaultStorage::with_read_fault(image.clone(), read);
            let mut allocation = Allocation::new();
            assert!(storage_init::mount_existing(&mut allocation, &mut storage).is_err());
            assert_eq!(storage.bytes, image, "read failure {read} changed storage");
            assert_eq!(storage.writes, 0, "read failure {read} caused a write");
            assert_eq!(storage.erases, 0, "read failure {read} caused an erase");
        }
    }

    #[test]
    fn one_corrupt_superblock_is_recovered_without_startup_writes() {
        let image = provisioned_image();
        let mut storage = FaultStorage::from_bytes(image);
        storage.corrupt(0, BLOCK_SIZE, 0x00);
        let corrupted = storage.snapshot();

        assert_eq!(read_record(&mut storage).unwrap(), OLD_RECORD);
        assert_eq!(storage.bytes, corrupted);
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.erases, 0);
    }

    #[test]
    fn corrupt_version_marker_is_rejected_without_mutation() {
        let image = provisioned_image();
        let mut storage = FaultStorage::from_bytes(image);
        Filesystem::mount_and_then(&mut storage, |filesystem| {
            filesystem.write(path!("/.rissokey-storage-format"), b"wrong-version\n")
        })
        .unwrap();
        let corrupted = storage.snapshot();
        storage.writes = 0;
        storage.erases = 0;

        let mut allocation = Allocation::new();
        assert!(storage_init::mount_existing(&mut allocation, &mut storage).is_err());
        assert_eq!(storage.bytes, corrupted);
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.erases, 0);
    }

    #[test]
    fn interrupted_version_marker_write_never_causes_startup_formatting() {
        let formatted = formatted_image();
        let mut successful = FaultStorage::from_bytes(formatted.clone());
        Filesystem::mount_and_then(&mut successful, |filesystem| {
            storage_init::write_storage_version(filesystem).map_err(|_| Error::IO)
        })
        .unwrap();
        let mutations = successful.mutations.clone();
        assert!(!mutations.is_empty());

        for (mutation, (_, len)) in mutations.iter().enumerate() {
            let aligned_half = (len / 2) / FaultStorage::WRITE_SIZE * FaultStorage::WRITE_SIZE;
            for prefix_bytes in [0, aligned_half, *len] {
                let mut interrupted = FaultStorage::with_fault(
                    formatted.clone(),
                    FaultPlan {
                        mutation,
                        prefix_bytes,
                    },
                );
                let result = Filesystem::mount_and_then(&mut interrupted, |filesystem| {
                    storage_init::write_storage_version(filesystem).map_err(|_| Error::IO)
                });
                assert!(
                    result.is_err(),
                    "fault {mutation}:{prefix_bytes} was not observed"
                );

                interrupted.plan = None;
                interrupted.failed = false;
                interrupted.writes = 0;
                interrupted.erases = 0;
                let after_interruption = interrupted.snapshot();
                let mut allocation = Allocation::new();
                let _ = storage_init::mount_existing(&mut allocation, &mut interrupted);
                assert_eq!(
                    interrupted.bytes, after_interruption,
                    "startup changed storage after marker fault {mutation}:{prefix_bytes}"
                );
                assert_eq!(
                    interrupted.writes, 0,
                    "startup wrote after marker fault {mutation}:{prefix_bytes}"
                );
                assert_eq!(
                    interrupted.erases, 0,
                    "startup erased after marker fault {mutation}:{prefix_bytes}"
                );
            }
        }
    }

    #[test]
    fn interrupted_rewrites_and_erases_keep_a_mountable_old_or_new_record() {
        let (original, replacement) = image_before_erase();
        let mut successful = FaultStorage::from_bytes(original.clone());
        Filesystem::mount_and_then(&mut successful, |filesystem| {
            filesystem.write(RECORD_PATH, replacement)
        })
        .unwrap();
        let mutations = successful.mutations.clone();
        assert!(!mutations.is_empty());
        assert!(
            mutations
                .iter()
                .any(|(kind, _)| *kind == MutationKind::Write),
            "rewrite workload did not issue a flash program operation"
        );
        assert!(
            mutations
                .iter()
                .any(|(kind, _)| *kind == MutationKind::Erase),
            "rewrite workload did not issue a flash erase operation"
        );

        for (mutation, (_, len)) in mutations.iter().enumerate() {
            let aligned_half = (len / 2) / FaultStorage::WRITE_SIZE * FaultStorage::WRITE_SIZE;
            for prefix_bytes in [0, aligned_half, *len] {
                let mut interrupted = FaultStorage::with_fault(
                    original.clone(),
                    FaultPlan {
                        mutation,
                        prefix_bytes,
                    },
                );
                let result = Filesystem::mount_and_then(&mut interrupted, |filesystem| {
                    filesystem.write(RECORD_PATH, replacement)
                });
                assert!(
                    result.is_err(),
                    "fault {mutation}:{prefix_bytes} was not observed"
                );
                interrupted.plan = None;
                interrupted.failed = false;
                interrupted.writes = 0;
                interrupted.erases = 0;
                let after_interruption = interrupted.snapshot();

                let record = read_record(&mut interrupted)
                    .unwrap_or_else(|error| panic!("fault {mutation}:{prefix_bytes}: {error}"));
                assert!(
                    record == OLD_RECORD || record == NEW_RECORD,
                    "fault {mutation}:{prefix_bytes} exposed a partial record"
                );
                assert_eq!(
                    interrupted.bytes, after_interruption,
                    "startup changed storage after update fault {mutation}:{prefix_bytes}"
                );
                assert_eq!(
                    interrupted.writes, 0,
                    "startup wrote after update fault {mutation}:{prefix_bytes}"
                );
                assert_eq!(
                    interrupted.erases, 0,
                    "startup erased after update fault {mutation}:{prefix_bytes}"
                );
            }
        }
    }

    #[test]
    fn corrupting_both_superblocks_never_triggers_implicit_format() {
        let mut storage = FaultStorage::from_bytes(provisioned_image());
        storage.corrupt(0, BLOCK_SIZE * 2, 0x00);
        let corrupted = storage.snapshot();
        storage.writes = 0;
        storage.erases = 0;

        let mut allocation = Allocation::new();
        assert!(storage_init::mount_existing(&mut allocation, &mut storage).is_err());
        assert_eq!(storage.bytes, corrupted);
        assert_eq!(storage.writes, 0);
        assert_eq!(storage.erases, 0);
    }
}
