#[cfg(test)]
#[path = "../../../src/request_completion.rs"]
mod request_completion;

#[cfg(test)]
mod tests {
    use core::task::Poll;
    use std::{env, fs, path::Path};

    use fido_authenticator::{Authenticator, Config, Conforming, Error, state::PersistentState};
    use heapless_bytes::Bytes;
    use littlefs2_core::{FileType, Metadata};
    use sha2::{Digest as _, Sha256};
    use tempfile::Builder;
    use trussed::{
        backend::BackendId,
        platform::Platform as _,
        store::Store as _,
        virt::{self, StorageConfig, StoreConfig},
    };
    use trussed_core::{
        ClientResult, Error as TrussedError, FilesystemClient, FutureResult, PollClient,
        api::{Reply, RequestVariant, reply},
    };
    use trussed_staging::virt::{BackendIds, Dispatcher};

    const STATE_PATH: &littlefs2_core::Path =
        littlefs2_core::path!("fido/dat/persistent-state.cbor");
    const MARKER_PATH: &littlefs2_core::Path =
        littlefs2_core::path!("fido/dat/persistent-state.init");

    fn sha256(path: &Path) -> [u8; 32] {
        Sha256::digest(fs::read(path).unwrap()).into()
    }

    fn run_command(
        command: ctaphid_dispatch::app::Command,
        request: &[u8],
        files: &[(&littlefs2_core::Path, &[u8])],
    ) -> (Vec<u8>, bool, bool, bool) {
        let temporary_root = env::var_os("TMPDIR").expect("TMPDIR must be set");
        let directory = Builder::new()
            .prefix("rissokey-persistent-state-")
            .tempdir_in(temporary_root)
            .unwrap();
        let image = directory.path().join("internal.store");
        let mut store_config = StoreConfig::ram();
        store_config.internal = StorageConfig::filesystem(image.clone());

        virt::with_platform(store_config, |platform| {
            let store = platform.store();
            let ifs = store.ifs();
            for (path, data) in files {
                ifs.create_dir_all(&path.parent().unwrap()).unwrap();
                ifs.write(path, data).unwrap();
            }
            let before = sha256(&image);
            let response = platform.run_client_with_backends(
                "fido",
                Dispatcher::default(),
                &[
                    BackendId::Custom(BackendIds::StagingBackend),
                    BackendId::Core,
                ],
                |client| {
                    let mut authenticator =
                        Authenticator::new(client, Conforming {}, Config::new(1024));
                    let mut response = Bytes::<1024>::new();
                    ctaphid_dispatch::app::App::call(
                        &mut authenticator,
                        command,
                        request,
                        response.as_mut_view(),
                    )
                    .unwrap();
                    response.to_vec()
                },
            );
            let after = sha256(&image);
            (
                response,
                before == after,
                ifs.exists(STATE_PATH),
                ifs.exists(MARKER_PATH),
            )
        })
    }

    fn run_get_info(files: &[(&littlefs2_core::Path, &[u8])]) -> (Vec<u8>, bool, bool, bool) {
        run_command(ctaphid_dispatch::app::Command::Cbor, &[0x04], files)
    }

    #[test]
    fn first_ctap_command_rejects_missing_state_without_writing_storage() {
        let (response, unchanged, state_exists, marker_exists) = run_get_info(&[]);
        assert_eq!(response, [Error::Other as u8]);
        assert!(unchanged);
        assert!(!state_exists);
        assert!(!marker_exists);
    }

    #[test]
    fn ab_confirmation_rejects_real_storage_errors_but_accepts_initialized_get_info() {
        use super::request_completion::{CborCompletion, ReplyError, complete_cbor};
        // App::call returns Ok for these real CTAP responses. The production
        // confirmation gate must distinguish their CTAP status bytes.
        for files in [
            &[][..],
            &[
                (STATE_PATH, &[0xa1][..]),
                (MARKER_PATH, PersistentState::INITIALIZATION_MARKER),
            ][..],
        ] {
            let (mut response, unchanged, _, _) = run_get_info(files);
            assert_eq!(response, [Error::Other as u8]);
            assert!(unchanged);
            assert_eq!(
                complete_cbor(true, &mut response, |bytes| {
                    assert_eq!(bytes, [Error::Other as u8]);
                    Ok(())
                }),
                Ok(CborCompletion::Failed)
            );
            assert!(response.iter().all(|byte| *byte == 0));
        }
        let (mut response, _, state_exists, marker_exists) =
            run_get_info(&[(MARKER_PATH, PersistentState::INITIALIZATION_MARKER)]);
        assert!(state_exists);
        assert!(!marker_exists);
        let mut interrupted_response = response.clone();
        assert_eq!(
            complete_cbor(true, &mut response, |bytes| {
                assert_eq!(bytes.first(), Some(&0));
                Ok(())
            }),
            Ok(CborCompletion::Succeeded)
        );
        assert_eq!(
            complete_cbor(true, &mut interrupted_response, |_| Err(
                ReplyError::NoPendingRequest
            )),
            Ok(CborCompletion::Interrupted)
        );
        assert!(response.iter().all(|byte| *byte == 0));
        assert!(interrupted_response.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn ctap1_command_rejects_missing_state_without_writing_storage() {
        let (response, unchanged, state_exists, marker_exists) = run_command(
            ctaphid_dispatch::app::Command::Msg,
            &[0x00, 0x03, 0x00, 0x00, 0x00],
            &[],
        );
        assert_eq!(response, [0x65, 0x00]);
        assert!(unchanged);
        assert!(!state_exists);
        assert!(!marker_exists);
    }

    #[test]
    fn truncated_state_is_rejected_without_writing_storage() {
        let (response, unchanged, state_exists, marker_exists) = run_get_info(&[
            (STATE_PATH, &[0xa1]),
            (MARKER_PATH, PersistentState::INITIALIZATION_MARKER),
        ]);
        assert_eq!(response, [Error::Other as u8]);
        assert!(unchanged);
        assert!(state_exists);
        assert!(marker_exists);
    }

    #[test]
    fn bit_flipped_state_is_rejected_without_writing_storage() {
        let mut corrupted = hex_literal::hex!(
            "a5726b65795f656e6372797074696f6e5f6b657950b19a5a2845e5ec71e3
             2a1b890892376c706b65795f7772617070696e675f6b6579f6781a636f6e
             73656375746976655f70696e5f6d69736d617463686573006870696e5f68
             6173689018ef1879187c1881181818f0182d18fb186418960718dd185d18
             3f188c18766974696d657374616d7009"
        );
        corrupted[0] ^= 0xff;
        let (response, unchanged, state_exists, marker_exists) =
            run_get_info(&[(STATE_PATH, &corrupted)]);
        assert_eq!(response, [Error::Other as u8]);
        assert!(unchanged);
        assert!(state_exists);
        assert!(!marker_exists);
    }

    #[test]
    fn malformed_marker_is_rejected_without_writing_storage() {
        let (response, unchanged, state_exists, marker_exists) =
            run_get_info(&[(MARKER_PATH, b"not-an-initialization-marker\n")]);
        assert_eq!(response, [Error::Other as u8]);
        assert!(unchanged);
        assert!(!state_exists);
        assert!(marker_exists);
    }

    #[test]
    fn valid_marker_authorizes_one_initialization() {
        let (response, unchanged, state_exists, marker_exists) =
            run_get_info(&[(MARKER_PATH, PersistentState::INITIALIZATION_MARKER)]);
        assert_eq!(response.first(), Some(&0));
        assert!(!unchanged);
        assert!(state_exists);
        assert!(!marker_exists);
    }

    struct ReadErrorClient;

    impl PollClient for ReadErrorClient {
        fn request<Rq: RequestVariant>(
            &mut self,
            _request: Rq,
        ) -> ClientResult<'_, Rq::Reply, Self> {
            Ok(FutureResult::new(self))
        }

        fn poll(&mut self) -> Poll<core::result::Result<Reply, TrussedError>> {
            Poll::Ready(Err(TrussedError::FilesystemReadFailure))
        }
    }

    impl FilesystemClient for ReadErrorClient {}

    struct StateReadErrorClient {
        replies: u8,
    }

    impl PollClient for StateReadErrorClient {
        fn request<Rq: RequestVariant>(
            &mut self,
            _request: Rq,
        ) -> ClientResult<'_, Rq::Reply, Self> {
            Ok(FutureResult::new(self))
        }

        fn poll(&mut self) -> Poll<core::result::Result<Reply, TrussedError>> {
            self.replies += 1;
            if self.replies == 1 {
                Poll::Ready(Ok(Reply::Metadata(reply::Metadata {
                    metadata: Some(Metadata::new(FileType::File, 1)),
                })))
            } else {
                Poll::Ready(Err(TrussedError::FilesystemReadFailure))
            }
        }
    }

    impl FilesystemClient for StateReadErrorClient {}

    #[test]
    fn metadata_read_error_is_rejected_without_initializing_memory_state() {
        let mut client = ReadErrorClient;
        let mut state = PersistentState::default();
        assert_eq!(
            state.load_if_not_initialised(&mut client, &Config::new(0)),
            Err(Error::Other)
        );
        assert_eq!(state, PersistentState::default());
    }

    #[test]
    fn state_file_read_error_is_rejected_without_initializing_memory_state() {
        let mut client = StateReadErrorClient { replies: 0 };
        let mut state = PersistentState::default();
        assert_eq!(
            state.load_if_not_initialised(&mut client, &Config::new(0)),
            Err(Error::Other)
        );
        assert_eq!(client.replies, 2);
        assert_eq!(state, PersistentState::default());
    }
}
