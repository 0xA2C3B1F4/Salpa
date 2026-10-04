//! Host lifecycle tests with real Trussed crypto, a fake clock and selected I/O faults.
//! No production clock override or test-approval feature is added to the firmware.

use super::pin::{PinProtocol, PinProtocolState, PinProtocolVersion, RpScope, SharedSecret};
use core::{task::Poll, time::Duration};
use ctap_types::{Error, ctap2::client_pin::Permissions};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::{cell::RefCell, rc::Rc};
use trussed::{
    backend::BackendId,
    virt::{self, StoreConfig},
};
use trussed_core::{
    ClientResult, CryptoClient, FutureResult, ManagementClient, PollClient,
    api::{self, Reply, RequestVariant, reply},
    mechanisms::{HmacSha256, P256},
    serde_extensions::{Extension, ExtensionClient},
    syscall, try_syscall,
    types::Location,
};
use trussed_hkdf::HkdfClient;
use trussed_staging::virt::{BackendIds, Dispatcher};

#[derive(Clone, Default)]
struct Clock(Arc<AtomicU64>);

impl Clock {
    fn set(&self, millis: u64) {
        self.0.store(millis, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
enum FaultTarget {
    StateWrite(usize),
    RemoveFile(&'static littlefs2_core::Path),
    DeleteAll(Location),
    ReadDirFirst,
    ReadDirNext(usize),
    CredentialRead(usize),
}

#[derive(Default)]
struct StorageFault {
    count: usize,
    commit_operation: Option<usize>,
    at: Option<usize>,
    after: bool,
    offline: bool,
    target: Option<FaultTarget>,
    target_hits: usize,
    false_delete: bool,
}

struct ClockClient<C> {
    fault: Rc<RefCell<StorageFault>>,
    fault_reply: bool,
    fail_after_reply: bool,
    inner: Rc<RefCell<C>>,
    clock: Clock,
    clock_reply: bool,
    false_delete_reply: bool,
}

impl<C: PollClient> PollClient for ClockClient<C> {
    fn request<Rq: RequestVariant>(&mut self, request: Rq) -> ClientResult<'_, Rq::Reply, Self> {
        let request: api::Request = request.into();
        let mutation = matches!(
            request,
            api::Request::GenerateKey(_)
                | api::Request::WriteFile(_)
                | api::Request::Rename(_)
                | api::Request::RemoveFile(_)
                | api::Request::Delete(_)
        );
        let mut fault = self.fault.borrow_mut();
        if mutation {
            fault.count += 1;
        }
        if matches!(&request, api::Request::Rename(rename) if rename.to == littlefs2_core::path!("rk-transaction").into())
        {
            fault.commit_operation = Some(fault.count);
        }
        let target_hit = match (&fault.target, &request) {
            (Some(FaultTarget::StateWrite(_)), api::Request::WriteFile(write))
                if write.path == littlefs2_core::path!("persistent-state.cbor").into() =>
            {
                fault.target_hits += 1;
                matches!(fault.target, Some(FaultTarget::StateWrite(n)) if fault.target_hits == n)
            }
            (Some(FaultTarget::RemoveFile(path)), api::Request::RemoveFile(remove)) => {
                remove.path == (*path).into()
            }
            (Some(FaultTarget::DeleteAll(location)), api::Request::DeleteAllKeys(delete)) => {
                delete.location == *location
            }
            (Some(FaultTarget::ReadDirFirst), api::Request::ReadDirFirst(_)) => true,
            (Some(FaultTarget::ReadDirNext(n)), api::Request::ReadDirNext(_)) => {
                let n = *n;
                fault.target_hits += 1;
                fault.target_hits == n
            }
            (Some(FaultTarget::CredentialRead(n)), api::Request::ReadFile(read))
                if read.path.as_str().starts_with("rk/") =>
            {
                let n = *n;
                fault.target_hits += 1;
                fault.target_hits == n
            }
            _ => false,
        };
        let hit = target_hit || (mutation && fault.at == Some(fault.count));
        self.false_delete_reply =
            hit && fault.false_delete && matches!(request, api::Request::Delete(_));
        if fault.offline || (hit && !fault.after) {
            fault.offline = true;
            self.fault_reply = true;
        } else if matches!(request, api::Request::Uptime(_)) {
            self.clock_reply = true;
        } else {
            let request = Rq::try_from(request).unwrap_or_else(|_| panic!("request type changed"));
            self.fail_after_reply = hit && fault.after;
            // The real request is polled through this wrapper's poll method.
            drop(self.inner.borrow_mut().request(request)?);
        }
        drop(fault);
        Ok(FutureResult::new(self))
    }

    fn poll(&mut self) -> Poll<Result<Reply, trussed_core::Error>> {
        if core::mem::take(&mut self.fault_reply) {
            if core::mem::take(&mut self.false_delete_reply) {
                return Poll::Ready(Ok(reply::Delete { success: false }.into()));
            }
            return Poll::Ready(Err(trussed_core::Error::FilesystemWriteFailure));
        }
        if core::mem::take(&mut self.clock_reply) {
            let millis = self.clock.0.load(Ordering::SeqCst);
            if millis == u64::MAX {
                return Poll::Ready(Err(trussed_core::Error::InternalError));
            }
            Poll::Ready(Ok(reply::Uptime {
                uptime: Duration::from_millis(millis),
            }
            .into()))
        } else {
            let reply = self.inner.borrow_mut().poll();
            if reply.is_ready() && core::mem::take(&mut self.fail_after_reply) {
                self.fault.borrow_mut().offline = true;
                if core::mem::take(&mut self.false_delete_reply) {
                    Poll::Ready(Ok(reply::Delete { success: false }.into()))
                } else {
                    Poll::Ready(Err(trussed_core::Error::FilesystemWriteFailure))
                }
            } else {
                reply
            }
        }
    }
}

impl<C: PollClient> CryptoClient for ClockClient<C> {}
impl<C: PollClient> HmacSha256 for ClockClient<C> {}
impl<C: PollClient> P256 for ClockClient<C> {}
impl<C: PollClient> trussed_core::mechanisms::Chacha8Poly1305 for ClockClient<C> {}
impl<C: PollClient> trussed_core::mechanisms::Aes256Cbc for ClockClient<C> {}
impl<C: PollClient> trussed_core::mechanisms::Sha256 for ClockClient<C> {}
impl<C: PollClient> trussed_core::mechanisms::Ed255 for ClockClient<C> {}
impl<C: PollClient> ManagementClient for ClockClient<C> {}
impl<C: PollClient> trussed_core::CertificateClient for ClockClient<C> {}
impl<C: PollClient> trussed_core::FilesystemClient for ClockClient<C> {}
impl<C: PollClient> trussed_core::UiClient for ClockClient<C> {}
impl<C: ExtensionClient<E>, E: Extension> ExtensionClient<E> for ClockClient<C> {
    fn id() -> u8 {
        C::id()
    }
}

fn run(test: impl FnOnce(&mut ClockClient<virt::Client<'_, Dispatcher>>, Clock)) {
    run_with_store(StoreConfig::ram(), test);
}

fn run_with_store(
    store: StoreConfig,
    test: impl FnOnce(&mut ClockClient<virt::Client<'_, Dispatcher>>, Clock),
) {
    run_with_store_files(store, &[], test);
}

fn run_with_store_files(
    store: StoreConfig,
    files: &[(&littlefs2_core::Path, &[u8])],
    test: impl FnOnce(&mut ClockClient<virt::Client<'_, Dispatcher>>, Clock),
) {
    use trussed::{platform::Platform as _, store::Store as _};
    virt::with_platform(store, |platform| {
        for (path, data) in files {
            platform
                .store()
                .ifs()
                .create_dir_all(&path.parent().unwrap())
                .unwrap();
            platform.store().ifs().write(path, data).unwrap();
        }
        platform.run_client_with_backends(
            "fido",
            Dispatcher::default(),
            &[
                BackendId::Custom(BackendIds::StagingBackend),
                BackendId::Core,
            ],
            |inner| {
                let clock = Clock::default();
                let mut client = ClockClient {
                    fault: Rc::default(),
                    fault_reply: false,
                    fail_after_reply: false,
                    inner: Rc::new(RefCell::new(inner)),
                    clock: clock.clone(),
                    clock_reply: false,
                    false_delete_reply: false,
                };
                test(&mut client, clock);
            },
        );
    });
}

fn issue<C: CryptoClient + ManagementClient + HkdfClient + HmacSha256 + P256>(
    client: &mut C,
    state: &mut PinProtocolState,
    version: PinProtocolVersion,
    permissions: Permissions,
    rp: Option<&str>,
) -> Vec<u8> {
    // Generated test-only wrapping key. No production identities or files.
    let key = syscall!(client.generate_secret_key(32, Location::Volatile)).key;
    let secret = SharedSecret::V1 { key_id: key };
    let encrypted = {
        let mut protocol = PinProtocol::new(client, state, version);
        let mut token = protocol.reset_and_begin_using_pin_token(false).unwrap();
        token.restrict(permissions, rp.map(|rp| rp.try_into().unwrap()));
        token.encrypt(&secret).unwrap()
    };
    let token = secret.decrypt(client, &encrypted).unwrap().to_vec();
    syscall!(client.delete(key));
    token
}

fn signature(token: &[u8], version: PinProtocolVersion, data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(token).unwrap();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    match version {
        PinProtocolVersion::V1 => result[..16].to_vec(),
        PinProtocolVersion::V2 => result.to_vec(),
    }
}

#[test]
fn unused_tokens_expire_at_thirty_seconds_for_both_protocols() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, clock| {
            let mut state = PinProtocolState::new(client);
            let token = issue(
                client,
                &mut state,
                version,
                Permissions::GET_ASSERTION,
                Some("example.test"),
            );
            let sig = signature(&token, version, b"request");
            clock.set(29_999);
            assert!(
                PinProtocol::new(client, &mut state, version)
                    .verify_pin_token(b"request", &sig)
                    .is_ok()
            );
            clock.set(30_000);
            assert!(matches!(
                PinProtocol::new(client, &mut state, version).verify_pin_token(b"request", &sig),
                Err(Error::PinAuthInvalid)
            ));
            clock.set(0); // An expired key cannot return when the clock changes.
            assert!(
                PinProtocol::new(client, &mut state, version)
                    .verify_pin_token(b"request", &sig)
                    .is_err()
            );
        });
    }
}

#[test]
fn authorized_use_allows_ten_minutes_but_never_extends_the_absolute_limit() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, clock| {
            let mut state = PinProtocolState::new(client);
            let token = issue(
                client,
                &mut state,
                version,
                Permissions::CREDENTIAL_MANAGEMENT,
                None,
            );
            let sig = signature(&token, version, b"request");
            for now in [29_999, 30_000, 599_999] {
                clock.set(now);
                let mut protocol = PinProtocol::new(client, &mut state, version);
                let token = protocol.verify_pin_token(b"request", &sig).unwrap();
                token
                    .require_permissions(Permissions::CREDENTIAL_MANAGEMENT)
                    .unwrap();
                token.require_valid_for_rp(RpScope::All).unwrap();
                token.mark_used();
            }
            clock.set(600_000);
            assert!(
                PinProtocol::new(client, &mut state, version)
                    .verify_pin_token(b"request", &sig)
                    .is_err()
            );
        });
    }
}

#[test]
fn invalid_hmac_lengths_and_values_never_extend_the_initial_lifetime() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, clock| {
            let mut state = PinProtocolState::new(client);
            let token = issue(
                client,
                &mut state,
                version,
                Permissions::GET_ASSERTION,
                Some("example.test"),
            );
            let sig = signature(&token, version, b"request");
            for length in [0, 1, 15, 16, 17, 31, 32, 33] {
                assert!(
                    PinProtocol::new(client, &mut state, version)
                        .verify_pin_token(b"request", &vec![0; length])
                        .is_err()
                );
            }
            for index in 0..sig.len() {
                let mut wrong = sig.clone();
                wrong[index] ^= 1;
                assert!(
                    PinProtocol::new(client, &mut state, version)
                        .verify_pin_token(b"request", &wrong)
                        .is_err()
                );
            }
            clock.set(30_000);
            assert!(
                PinProtocol::new(client, &mut state, version)
                    .verify_pin_token(b"request", &sig)
                    .is_err()
            );
        });
    }
}

#[test]
fn missing_permissions_wrong_rp_and_unscoped_management_are_denied() {
    run(|client, clock| {
        let mut state = PinProtocolState::new(client);
        let version = PinProtocolVersion::V2;
        let token = issue(
            client,
            &mut state,
            version,
            Permissions::GET_ASSERTION,
            Some("example.test"),
        );
        let sig = signature(&token, version, b"request");
        let mut protocol = PinProtocol::new(client, &mut state, version);
        let token = protocol.verify_pin_token(b"request", &sig).unwrap();
        assert!(
            token
                .require_permissions(Permissions::MAKE_CREDENTIAL)
                .is_err()
        );
        assert!(
            token
                .require_valid_for_rp(RpScope::RpId("other.test"))
                .is_err()
        );
        assert!(token.require_valid_for_rp(RpScope::All).is_err());
        assert!(
            token
                .require_valid_for_rp(RpScope::RpIdHash(&[0; 32]))
                .is_err()
        );
        token
            .require_valid_for_rp(RpScope::RpId("example.test"))
            .unwrap();
        clock.set(30_000);
        assert!(
            PinProtocol::new(client, &mut state, version)
                .verify_pin_token(b"request", &sig)
                .is_err()
        );
    });
}

#[test]
fn legacy_token_binds_first_rp_and_new_grants_invalidate_both_protocols() {
    run(|client, _| {
        let mut state = PinProtocolState::new(client);
        let token = issue(
            client,
            &mut state,
            PinProtocolVersion::V1,
            Permissions::GET_ASSERTION,
            None,
        );
        let sig = signature(&token, PinProtocolVersion::V1, b"request");
        let mut protocol = PinProtocol::new(client, &mut state, PinProtocolVersion::V1);
        let token = protocol.verify_pin_token(b"request", &sig).unwrap();
        token.bind_rp_if_unset("first.test").unwrap();
        assert!(token.bind_rp_if_unset("second.test").is_err());
        issue(
            client,
            &mut state,
            PinProtocolVersion::V2,
            Permissions::GET_ASSERTION,
            Some("second.test"),
        );
        assert!(
            PinProtocol::new(client, &mut state, PinProtocolVersion::V1)
                .verify_pin_token(b"request", &sig)
                .is_err()
        );
        assert!(
            PinProtocol::new(client, &mut state, PinProtocolVersion::V2)
                .verify_pin_token(b"request", &sig)
                .is_err()
        );
    });
}

#[test]
fn clock_failure_and_clock_reversal_delete_the_token() {
    for failure in [99, u64::MAX] {
        run(|client, clock| {
            clock.set(100);
            let mut state = PinProtocolState::new(client);
            let version = PinProtocolVersion::V2;
            let token = issue(
                client,
                &mut state,
                version,
                Permissions::CREDENTIAL_MANAGEMENT,
                None,
            );
            let sig = signature(&token, version, b"request");
            clock.set(failure);
            assert!(
                PinProtocol::new(client, &mut state, version)
                    .verify_pin_token(b"request", &sig)
                    .is_err()
            );
            clock.set(101);
            assert!(
                PinProtocol::new(client, &mut state, version)
                    .verify_pin_token(b"request", &sig)
                    .is_err()
            );
        });
    }
}

#[test]
fn physical_presence_consumes_uv_and_permissions_except_large_blob_write() {
    run(|client, _| {
        let mut state = PinProtocolState::new(client);
        let version = PinProtocolVersion::V2;
        let token = issue(
            client,
            &mut state,
            version,
            Permissions::GET_ASSERTION | Permissions::LARGE_BLOB_WRITE,
            Some("example.test"),
        );
        let sig = signature(&token, version, b"request");
        state.consume_user_presence();
        let mut protocol = PinProtocol::new(client, &mut state, version);
        let token = protocol.verify_pin_token(b"request", &sig).unwrap();
        assert!(token.require_user_verified().is_err());
        assert!(
            token
                .require_permissions(Permissions::GET_ASSERTION)
                .is_err()
        );
        token
            .require_permissions(Permissions::LARGE_BLOB_WRITE)
            .unwrap();
        protocol.reset_pin_tokens();
        assert!(protocol.verify_pin_token(b"request", &sig).is_err());
    });
}

// Exercise the public CTAP dispatcher as well as the focused state-machine
// tests above. The only consent bypass is Silent in this host-only test crate.
type TestAuthenticator<C> =
    fido_authenticator::Authenticator<fido_authenticator::Silent, ClockClient<C>>;

fn authenticator<C: PollClient>(client: &mut ClockClient<C>) -> TestAuthenticator<C>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    use trussed_core::FilesystemClient;
    syscall!(
        client.write_file(
            Location::Internal,
            littlefs2_core::path!("persistent-state.init").into(),
            fido_authenticator::state::PersistentState::INITIALIZATION_MARKER
                .try_into()
                .unwrap(),
            None
        )
    );
    reopen(client)
}

fn reopen<C: PollClient>(client: &mut ClockClient<C>) -> TestAuthenticator<C>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    reopen_with_config(client, fido_authenticator::Config::new(1024))
}

fn reopen_with_config<C: PollClient>(
    client: &mut ClockClient<C>,
    config: fido_authenticator::Config,
) -> TestAuthenticator<C>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let copy = ClockClient {
        fault: client.fault.clone(),
        fault_reply: false,
        fail_after_reply: false,
        inner: client.inner.clone(),
        clock: client.clock.clone(),
        clock_reply: false,
        false_delete_reply: false,
    };
    let mut auth =
        fido_authenticator::Authenticator::new(copy, fido_authenticator::Silent {}, config);
    assert_eq!(command(&mut auth, &[4])[0], 0);
    auth
}

fn command<C>(auth: &mut TestAuthenticator<C>, data: &[u8]) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let mut response = heapless_bytes::Bytes::<1024>::new();
    ctaphid_dispatch::app::App::call(
        auth,
        ctaphid_dispatch::app::Command::Cbor,
        data,
        response.as_mut_view(),
    )
    .unwrap();
    response.to_vec()
}

fn pin_request(
    version: PinProtocolVersion,
    sub: u8,
) -> ctap_types::ctap2::client_pin::Request<'static> {
    // Decode the required fields; the public request is non_exhaustive.
    let mut request: ctap_types::ctap2::client_pin::Request<'static> =
        cbor_smol::cbor_deserialize(&[0xa2, 1, 1, 2, 1]).unwrap();
    request.pin_protocol = Some(u8::from(version));
    request.sub_command = cbor_smol::cbor_deserialize(&[sub]).unwrap();
    request
}

fn client_pin<C>(
    auth: &mut TestAuthenticator<C>,
    request: &ctap_types::ctap2::client_pin::Request<'_>,
) -> Result<ctap_types::ctap2::client_pin::Response, Error>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let mut data = heapless_bytes::Bytes::<1024>::new();
    data.push(6).unwrap();
    cbor_smol::cbor_serialize_to(request, &mut data).unwrap();
    let response = command(auth, &data);
    if response[0] != 0 {
        return Err([
            Error::PinInvalid,
            Error::PinAuthInvalid,
            Error::PinAuthBlocked,
            Error::PinBlocked,
            Error::MissingParameter,
            Error::UnauthorizedPermission,
            Error::InvalidParameter,
            Error::Other,
        ]
        .into_iter()
        .find(|error| *error as u8 == response[0])
        .unwrap_or_else(|| panic!("unexpected CTAP status {}", response[0])));
    }
    if response.len() == 1 {
        return Ok(Default::default());
    }
    Ok(cbor_smol::cbor_deserialize(&response[1..]).unwrap())
}

fn exchange<C: PollClient>(
    client: &mut ClockClient<C>,
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
) -> (cosey::EcdhEsHkdf256PublicKey, SharedSecret)
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let peer = client_pin(auth, &pin_request(version, 2))
        .unwrap()
        .key_agreement
        .unwrap();
    let mut state = PinProtocolState::new(client);
    let mut protocol = PinProtocol::new(client, &mut state, version);
    let public = protocol.key_agreement_key();
    let secret = protocol.shared_secret(&peer).unwrap();
    // The state owns cached shared-secret handles; keep them for this exchange.
    // All virtual keys are discarded with the RAM platform at test end.
    (public, secret)
}

fn set_or_change_pin<C: PollClient>(
    client: &mut ClockClient<C>,
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
    old: Option<&str>,
    new: &str,
) where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    assert!(store_pin_with_fault(client, auth, version, old, new, None).is_ok());
}

fn store_pin_with_fault<C: PollClient>(
    client: &mut ClockClient<C>,
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
    old: Option<&str>,
    new: &str,
    fault: Option<StorageFault>,
) -> Result<(), Error>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    use sha2::Digest;
    let (public, secret) = exchange(client, auth, version);
    let mut padded = [0; 64];
    padded[..new.len()].copy_from_slice(new.as_bytes());
    let encrypted = secret.encrypt(client, &padded);
    let hash = old.map(|old| secret.encrypt(client, &Sha256::digest(old.as_bytes())[..16]));
    let mut data = encrypted.to_vec();
    if let Some(hash) = &hash {
        data.extend_from_slice(hash);
    }
    let key = match secret {
        SharedSecret::V1 { key_id } => key_id,
        SharedSecret::V2 { hmac_key_id, .. } => hmac_key_id,
    };
    let signature = syscall!(client.sign_hmacsha256(key, &data)).signature;
    let signature = if matches!(version, PinProtocolVersion::V1) {
        &signature[..16]
    } else {
        &signature[..]
    };
    let mut request = pin_request(version, if old.is_some() { 4 } else { 3 });
    request.key_agreement = Some(public);
    request.new_pin_enc = Some((&encrypted[..]).into());
    request.pin_hash_enc = hash.as_ref().map(|hash| (&hash[..]).into());
    request.pin_auth = Some(signature.into());
    if let Some(fault) = fault {
        *client.fault.borrow_mut() = fault;
    }
    let result = client_pin(auth, &request).map(|_| ());
    if !client.fault.borrow().offline {
        secret.delete(client);
    }
    result
}

fn grant<C: PollClient>(
    client: &mut ClockClient<C>,
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
    pin: &str,
    permissions: u8,
    rp: Option<&str>,
) -> Result<Vec<u8>, Error>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    grant_with_fault(client, auth, version, pin, permissions, rp, None)
}

fn grant_with_fault<C: PollClient>(
    client: &mut ClockClient<C>,
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
    pin: &str,
    permissions: u8,
    rp: Option<&str>,
    fault: Option<StorageFault>,
) -> Result<Vec<u8>, Error>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    use sha2::Digest;
    let (public, secret) = exchange(client, auth, version);
    let encrypted = secret.encrypt(client, &Sha256::digest(pin.as_bytes())[..16]);
    let mut request = pin_request(version, 9);
    request.key_agreement = Some(public);
    request.pin_hash_enc = Some((&encrypted[..]).into());
    request.permissions = Some(permissions);
    request.rp_id = rp;
    if let Some(fault) = fault {
        *client.fault.borrow_mut() = fault;
    }
    let result = client_pin(auth, &request).map(|response| {
        secret
            .decrypt(client, &response.pin_token.unwrap())
            .unwrap()
            .to_vec()
    });
    if !client.fault.borrow().offline {
        secret.delete(client);
    }
    result
}

fn metadata<C>(auth: &mut TestAuthenticator<C>, version: PinProtocolVersion, signature: &[u8]) -> u8
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    // credentialManagement: subcommand GetCredsMetadata, protocol, authParam.
    let mut request = vec![0x0a, 0xa3, 1, 1, 3, u8::from(version), 4];
    if signature.len() < 24 {
        request.push(0x40 + signature.len() as u8);
    } else {
        request.extend_from_slice(&[0x58, signature.len() as u8]);
    }
    request.extend_from_slice(signature);
    command(auth, &request)[0]
}

#[test]
fn ctap_dispatcher_expiry_bad_auth_and_pin_change_invalidate_authorizations() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, clock| {
            let mut auth = authenticator(client);
            set_or_change_pin(client, &mut auth, version, None, "test-only-first");
            let token = grant(client, &mut auth, version, "test-only-first", 4, None).unwrap();
            let sig = signature(&token, version, &[1]);
            assert_eq!(metadata(&mut auth, version, &sig), 0);
            for length in [0, 1, 15, 16, 17, 31, 32, 33] {
                assert_ne!(metadata(&mut auth, version, &vec![0; length]), 0);
            }
            assert_eq!(
                client_pin(&mut auth, &pin_request(version, 1))
                    .unwrap()
                    .retries,
                Some(8)
            );
            clock.set(600_000);
            assert_eq!(
                metadata(&mut auth, version, &sig),
                Error::PinAuthInvalid as u8
            );
            let token = grant(client, &mut auth, version, "test-only-first", 4, None).unwrap();
            let sig = signature(&token, version, &[1]);
            set_or_change_pin(
                client,
                &mut auth,
                version,
                Some("test-only-first"),
                "test-only-second",
            );
            assert_eq!(
                metadata(&mut auth, version, &sig),
                Error::PinAuthInvalid as u8
            );
            assert!(grant(client, &mut auth, version, "test-only-second", 4, None).is_ok());
        });
    }
}

#[test]
fn ctap_permissions_reset_and_pin_retry_escalation() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, clock| {
            let mut auth = authenticator(client);
            set_or_change_pin(client, &mut auth, version, None, "synthetic-pin");
            assert_eq!(
                grant(client, &mut auth, version, "synthetic-pin", 2, None),
                Err(Error::MissingParameter)
            );
            let token = grant(client, &mut auth, version, "synthetic-pin", 4, None).unwrap();
            let sig = signature(&token, version, &[1]);
            clock.set(30_000);
            assert_eq!(
                metadata(&mut auth, version, &sig),
                Error::PinAuthInvalid as u8
            );
            // Wrong PIN retains persistent and per-power-cycle attempt limits.
            for (attempt, expected) in [
                (1, Error::PinInvalid),
                (2, Error::PinInvalid),
                (3, Error::PinAuthBlocked),
            ] {
                assert_eq!(
                    grant(client, &mut auth, version, "wrong-test-pin", 4, None),
                    Err(expected)
                );
                assert_eq!(
                    client_pin(&mut auth, &pin_request(version, 1))
                        .unwrap()
                        .retries,
                    Some(8 - attempt)
                );
            }
            assert_eq!(
                grant(client, &mut auth, version, "synthetic-pin", 4, None),
                Err(Error::PinAuthBlocked)
            );
        });
        run(|client, _| {
            let mut auth = authenticator(client);
            set_or_change_pin(client, &mut auth, version, None, "synthetic-pin");
            let token = grant(client, &mut auth, version, "synthetic-pin", 4, None).unwrap();
            let sig = signature(&token, version, &[1]);
            assert_eq!(command(&mut auth, &[7]), [0]);
            assert_ne!(metadata(&mut auth, version, &sig), 0);
            set_or_change_pin(client, &mut auth, version, None, "new-test-pin");
            assert_eq!(
                metadata(&mut auth, version, &sig),
                Error::PinAuthInvalid as u8
            );
        });
    }
}

#[test]
fn persistent_eight_attempt_limit_survives_runtime_recreation() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, _| {
            let mut auth = authenticator(client);
            set_or_change_pin(client, &mut auth, version, None, "synthetic-pin");
            assert_eq!(
                grant(client, &mut auth, version, "wrong", 4, None),
                Err(Error::PinInvalid)
            );
            assert!(grant(client, &mut auth, version, "synthetic-pin", 4, None).is_ok());
            assert_eq!(
                client_pin(&mut auth, &pin_request(version, 1))
                    .unwrap()
                    .retries,
                Some(8)
            );
            for attempt in 1..=8 {
                let expected = if attempt == 8 {
                    Error::PinBlocked
                } else if attempt % 3 == 0 {
                    Error::PinAuthBlocked
                } else {
                    Error::PinInvalid
                };
                assert_eq!(
                    grant(client, &mut auth, version, "wrong", 4, None),
                    Err(expected)
                );
                assert_eq!(
                    client_pin(&mut auth, &pin_request(version, 1))
                        .unwrap()
                        .retries,
                    Some(8 - attempt)
                );
                if attempt % 3 == 0 {
                    auth = reopen(client);
                }
            }
            auth = reopen(client);
            assert_eq!(
                grant(client, &mut auth, version, "synthetic-pin", 4, None),
                Err(Error::PinBlocked)
            );
        });
    }
}

#[test]
fn restoring_old_valid_state_restores_pin_attempts_on_the_host() {
    use trussed_core::FilesystemClient;

    // Characterize a known limitation, not an accepted security property.
    // This is the real CTAP dispatcher over RAM-only Trussed storage. It does
    // not emulate ESP flash encryption or demonstrate physical flash access.
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, _| {
            let mut auth = authenticator(client);
            set_or_change_pin(client, &mut auth, version, None, "synthetic-pin");
            let path = littlefs2_core::path!("persistent-state.cbor");
            let snapshot = syscall!(client.read_file(Location::Internal, path.into())).data;

            for attempt in 1..=8 {
                let expected = if attempt == 8 {
                    Error::PinBlocked
                } else if attempt % 3 == 0 {
                    Error::PinAuthBlocked
                } else {
                    Error::PinInvalid
                };
                assert_eq!(
                    grant(client, &mut auth, version, "wrong", 4, None),
                    Err(expected)
                );
                if attempt % 3 == 0 {
                    auth = reopen(client);
                }
            }
            auth = reopen(client);
            assert_eq!(
                grant(client, &mut auth, version, "synthetic-pin", 4, None),
                Err(Error::PinBlocked)
            );

            // Restore exact previously valid bytes, without editing the
            // counter or changing code, keys, configuration or test clock.
            syscall!(client.write_file(Location::Internal, path.into(), snapshot, None));
            auth = reopen(client);
            assert_eq!(
                client_pin(&mut auth, &pin_request(version, 1))
                    .unwrap()
                    .retries,
                Some(8)
            );
            assert_eq!(
                grant(client, &mut auth, version, "wrong", 4, None),
                Err(Error::PinInvalid)
            );
            assert_eq!(
                client_pin(&mut auth, &pin_request(version, 1))
                    .unwrap()
                    .retries,
                Some(7)
            );
            assert!(grant(client, &mut auth, version, "synthetic-pin", 4, None).is_ok());
        });
    }
}

#[test]
fn new_ctap_grant_invalidates_old_protocol_and_management_respects_rp_scope() {
    run(|client, _| {
        let mut auth = authenticator(client);
        set_or_change_pin(
            client,
            &mut auth,
            PinProtocolVersion::V1,
            None,
            "synthetic-pin",
        );
        let old = grant(
            client,
            &mut auth,
            PinProtocolVersion::V1,
            "synthetic-pin",
            4,
            None,
        )
        .unwrap();
        let new = grant(
            client,
            &mut auth,
            PinProtocolVersion::V2,
            "synthetic-pin",
            4,
            Some("example.test"),
        )
        .unwrap();
        assert_eq!(
            metadata(
                &mut auth,
                PinProtocolVersion::V1,
                &signature(&old, PinProtocolVersion::V1, &[1])
            ),
            Error::PinAuthInvalid as u8
        );
        assert_eq!(
            metadata(
                &mut auth,
                PinProtocolVersion::V2,
                &signature(&new, PinProtocolVersion::V2, &[1])
            ),
            Error::PinAuthInvalid as u8
        );
        assert_eq!(
            client_pin(&mut auth, &pin_request(PinProtocolVersion::V2, 1))
                .unwrap()
                .retries,
            Some(8)
        );
    });
}

#[test]
fn malformed_encrypted_pin_hashes_still_consume_pin_attempts() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        for malformed_cipher in [false, true] {
            run(|client, _| {
                let mut auth = authenticator(client);
                set_or_change_pin(client, &mut auth, version, None, "synthetic-pin");
                let (public, secret) = exchange(client, &mut auth, version);
                let encrypted = if malformed_cipher {
                    vec![0; 17] // Not a valid CBC frame in either protocol.
                } else {
                    secret.encrypt(client, &[0; 32]).to_vec() // Wrong plaintext length.
                };
                let mut request = pin_request(version, 9);
                request.key_agreement = Some(public);
                request.pin_hash_enc = Some(encrypted.as_slice().into());
                request.permissions = Some(4);
                assert_eq!(client_pin(&mut auth, &request), Err(Error::PinInvalid));
                assert_eq!(
                    client_pin(&mut auth, &pin_request(version, 1))
                        .unwrap()
                        .retries,
                    Some(7)
                );
                secret.delete(client);
            });
        }
    }
}

fn make_resident<C>(auth: &mut TestAuthenticator<C>, user: u8) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    make_credential(auth, user, true, false)
}

fn make_credential<C>(
    auth: &mut TestAuthenticator<C>,
    user: u8,
    resident: bool,
    invalid_exclude: bool,
) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    make_credential_for_rp(auth, user, resident, invalid_exclude, "example.com")
}

fn make_credential_for_rp<C>(
    auth: &mut TestAuthenticator<C>,
    user: u8,
    resident: bool,
    invalid_exclude: bool,
    rp: &str,
) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    // Synthetic RP/user and ES256, resident credential requested.
    let mut request = vec![1, if invalid_exclude { 0xa6 } else { 0xa5 }, 1, 0x58, 32];
    request.extend_from_slice(&[0x42; 32]);
    request.extend_from_slice(b"\x02\xa1\x62id");
    assert!(rp.len() < 24);
    request.push(0x60 + rp.len() as u8);
    request.extend_from_slice(rp.as_bytes());
    request.extend_from_slice(b"\x03\xa1\x62id\x41");
    request.push(user);
    request.extend_from_slice(b"\x04\x81\xa2\x63alg\x26\x64type\x6apublic-key\x07\xa1\x62rk");
    request.push(if resident { 0xf5 } else { 0xf4 });
    if invalid_exclude {
        request.extend_from_slice(b"\x05\x81\xa2\x62id\x41\x00\x64type\x6apublic-key");
    }
    command(auth, &request)
}

fn allowlist_assertion<C>(auth: &mut TestAuthenticator<C>, id: &[u8]) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let mut request = b"\x02\xa3\x01\x6bexample.com\x02\x58\x20".to_vec();
    request.extend_from_slice(&[0x43; 32]);
    request.extend_from_slice(b"\x03\x81\xa2\x62id");
    if id.len() < 24 {
        request.push(0x40 + id.len() as u8);
    } else if id.len() < 256 {
        request.extend_from_slice(&[0x58, id.len() as u8]);
    } else {
        request.push(0x59);
        request.extend_from_slice(&(id.len() as u16).to_be_bytes());
    }
    request.extend_from_slice(id);
    request.extend_from_slice(b"\x64type\x6apublic-key");
    command(auth, &request)
}

fn resident_assertion<C>(auth: &mut TestAuthenticator<C>) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let mut request = b"\x02\xa2\x01\x6bexample.com\x02\x58\x20".to_vec();
    request.extend_from_slice(&[0x43; 32]);
    command(auth, &request)
}

#[test]
fn assertion_continuations_expire_and_refresh_with_a_monotonic_clock() {
    run(|client, clock| {
        let mut auth = authenticator(client);
        for user in 0..3 {
            assert_eq!(make_resident(&mut auth, user)[0], 0);
        }
        for (elapsed, allowed) in [
            (29_999, true),
            (30_000, true),
            (30_001, false),
            (31_000, false),
        ] {
            clock.set(100_000);
            assert_eq!(resident_assertion(&mut auth)[0], 0);
            clock.set(100_000 + elapsed);
            assert_eq!(
                command(&mut auth, &[8])[0],
                if allowed { 0 } else { Error::NotAllowed as u8 }
            );
            if allowed {
                clock.set(100_000 + elapsed + 29_999);
                assert_eq!(command(&mut auth, &[8])[0], 0);
            } else {
                clock.set(100_001);
                assert_eq!(command(&mut auth, &[8])[0], Error::NotAllowed as u8);
            }
        }
        for invalid_time in [99_999, u64::MAX] {
            clock.set(100_000);
            assert_eq!(resident_assertion(&mut auth)[0], 0);
            clock.set(invalid_time);
            assert_eq!(command(&mut auth, &[8])[0], Error::NotAllowed as u8);
        }
    });
}

#[test]
fn salpa_get_info_never_advertises_ctap1() {
    run(|client, _clock| {
        drop(authenticator(client));
        let config = super::config::fido_config();
        let mut state = fido_authenticator::state::PersistentState::default();
        state.load_if_not_initialised(client, &config).unwrap();
        for always_uv in [false, true] {
            if always_uv {
                state.toggle_always_uv(client).unwrap();
            }
            let copy = ClockClient {
                fault: client.fault.clone(),
                fault_reply: false,
                fail_after_reply: false,
                inner: client.inner.clone(),
                clock: client.clock.clone(),
                clock_reply: false,
                false_delete_reply: false,
            };
            let mut auth = fido_authenticator::Authenticator::new(
                copy,
                fido_authenticator::Silent {},
                config.clone(),
            );
            let response = command(&mut auth, &[4]);
            assert_eq!(response[0], 0);
            assert!(!response.windows(6).any(|bytes| bytes == b"U2F_V2"));
            assert!(response.windows(8).any(|bytes| bytes == b"FIDO_2_0"));
        }
    });
}

fn created_id(response: &[u8]) -> Vec<u8> {
    assert_eq!(response[0], 0);
    let response: ctap_types::ctap2::make_credential::Response =
        cbor_smol::cbor_deserialize(&response[1..]).unwrap();
    let length = u16::from_be_bytes(response.auth_data[53..55].try_into().unwrap()) as usize;
    response.auth_data[55..55 + length].to_vec()
}

fn filesystem_store(image: &std::path::Path) -> StoreConfig<'_> {
    let mut config = StoreConfig::ram();
    config.internal = virt::StorageConfig::filesystem(image.to_path_buf());
    config
}

fn assert_latched<C: PollClient>(auth: &mut TestAuthenticator<C>, client: &mut ClockClient<C>)
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    // The backend first remains offline, then becomes writable. Neither case
    // may accept mutated RAM or perform a retry/automatic recovery write.
    assert_eq!(command(auth, &[4]), [Error::Other as u8]);
    *client.fault.borrow_mut() = StorageFault::default();
    for request in [&[4][..], &[6, 0xa2, 1, 1, 2, 1][..], &[7][..]] {
        assert_eq!(command(auth, request), [Error::Other as u8]);
    }
    assert_eq!(client.fault.borrow().count, 0);
}

#[test]
fn pin_persistence_errors_stop_ctap_and_reboot_uses_only_committed_state() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        for operation in ["set", "change", "retry", "retry-reset"] {
            for after in [false, true] {
                let directory = tempfile::Builder::new()
                    .prefix("salpa-pin-save-fault-")
                    .tempdir_in(std::env::var_os("TMPDIR").unwrap())
                    .unwrap();
                let image = directory.path().join("internal.store");
                run_with_store(filesystem_store(&image), |client, _| {
                    let mut auth = authenticator(client);
                    let mut existing_token = None;
                    if operation != "set" {
                        set_or_change_pin(client, &mut auth, version, None, "synthetic-old-pin");
                        existing_token = Some(
                            grant(client, &mut auth, version, "synthetic-old-pin", 4, None)
                                .unwrap(),
                        );
                    }
                    let fault = StorageFault {
                        target: Some(FaultTarget::StateWrite(match operation {
                            "change" => 3,
                            "retry-reset" => 2,
                            _ => 1,
                        })),
                        after,
                        ..Default::default()
                    };
                    let result = match operation {
                        "set" => store_pin_with_fault(
                            client,
                            &mut auth,
                            version,
                            None,
                            "synthetic-new-pin",
                            Some(fault),
                        ),
                        "change" => store_pin_with_fault(
                            client,
                            &mut auth,
                            version,
                            Some("synthetic-old-pin"),
                            "synthetic-new-pin",
                            Some(fault),
                        ),
                        _ => grant_with_fault(
                            client,
                            &mut auth,
                            version,
                            if operation == "retry" {
                                "wrong-pin"
                            } else {
                                "synthetic-old-pin"
                            },
                            4,
                            None,
                            Some(fault),
                        )
                        .map(|_| ()),
                    };
                    assert_eq!(result, Err(Error::Other), "{operation}, after={after}");
                    assert!(client.fault.borrow().offline);
                    // Existing issued tokens must not turn failed cleanup into
                    // a panic, or authorize the next request when I/O returns.
                    if let Some(token) = existing_token {
                        let sig = signature(&token, version, &[1]);
                        assert_eq!(metadata(&mut auth, version, &sig), Error::Other as u8);
                    }
                    assert_latched(&mut auth, client);
                });
                // A fresh platform has no cached RAM or volatile authorization.
                run_with_store(filesystem_store(&image), |client, _| {
                    let mut auth = reopen(client);
                    let pin_is_set = !(operation == "set" && !after);
                    let info = command(&mut auth, &[4]);
                    let info: ctap_types::ctap2::get_info::Response =
                        cbor_smol::cbor_deserialize(&info[1..]).unwrap();
                    assert_eq!(info.options.unwrap().client_pin, Some(pin_is_set));
                    let retries = if (operation == "retry" && after)
                        || (operation == "retry-reset" && !after)
                    {
                        7
                    } else {
                        8
                    };
                    assert_eq!(
                        client_pin(&mut auth, &pin_request(version, 1))
                            .unwrap()
                            .retries,
                        Some(retries),
                    );
                    if pin_is_set {
                        let committed_new = after && matches!(operation, "set" | "change");
                        let accepted = if committed_new {
                            "synthetic-new-pin"
                        } else {
                            "synthetic-old-pin"
                        };
                        assert!(grant(client, &mut auth, version, accepted, 4, None).is_ok());
                        let rejected = if committed_new {
                            "synthetic-old-pin"
                        } else {
                            "synthetic-new-pin"
                        };
                        assert_eq!(
                            grant(client, &mut auth, version, rejected, 4, None),
                            Err(Error::PinInvalid),
                        );
                    } else {
                        set_or_change_pin(client, &mut auth, version, None, "fresh-pin");
                        assert!(grant(client, &mut auth, version, "fresh-pin", 4, None).is_ok());
                    }
                });
            }
        }
    }
}

#[test]
fn serialization_failure_latches_state_without_writing_or_loading_defaults() {
    use ctap_types::ctap2::config::{MAX_MIN_PIN_LENGTH_RP_IDS, MAX_RP_ID_LENGTH};
    use trussed_core::FilesystemClient;
    run(|client, _| {
        drop(authenticator(client));
        let config = fido_authenticator::Config::new(1024);
        let mut state = fido_authenticator::state::PersistentState::default();
        state.load_if_not_initialised(client, &config).unwrap();
        let path = littlefs2_core::path!("persistent-state.cbor");
        let before = syscall!(client.read_file(Location::Internal, path.into())).data;
        let mut rp_ids = heapless::Vec::new();
        for _ in 0..MAX_MIN_PIN_LENGTH_RP_IDS {
            let mut rp = heapless::String::<MAX_RP_ID_LENGTH>::new();
            for _ in 0..MAX_RP_ID_LENGTH {
                rp.push('a').unwrap();
            }
            rp_ids.push(rp).unwrap();
        }
        client.fault.borrow_mut().count = 0;
        assert_eq!(
            state.set_min_pin_length_rp_ids(client, rp_ids),
            Err(Error::Other)
        );
        assert_eq!(client.fault.borrow().count, 0);
        assert_eq!(
            state.load_if_not_initialised(client, &config),
            Err(Error::Other)
        );
        assert_eq!(state.save(client), Err(Error::Other));
        assert_eq!(client.fault.borrow().count, 0);
        assert_eq!(
            syscall!(client.read_file(Location::Internal, path.into())).data,
            before
        );
        let mut rebooted = fido_authenticator::state::PersistentState::default();
        rebooted.load_if_not_initialised(client, &config).unwrap();
        assert!(rebooted.min_pin_length_rp_ids().is_empty());
    });
}

#[test]
fn initial_state_write_failure_latches_the_original_uninitialized_state() {
    use trussed_core::FilesystemClient;
    for after in [false, true] {
        run(|client, _| {
            syscall!(
                client.write_file(
                    Location::Internal,
                    littlefs2_core::path!("persistent-state.init").into(),
                    fido_authenticator::state::PersistentState::INITIALIZATION_MARKER
                        .try_into()
                        .unwrap(),
                    None,
                )
            );
            let config = fido_authenticator::Config::new(1024);
            let mut state = fido_authenticator::state::PersistentState::default();
            *client.fault.borrow_mut() = StorageFault {
                target: Some(FaultTarget::StateWrite(1)),
                after,
                ..Default::default()
            };
            assert_eq!(
                state.load_if_not_initialised(client, &config),
                Err(Error::Other)
            );
            *client.fault.borrow_mut() = StorageFault::default();
            assert_eq!(
                state.load_if_not_initialised(client, &config),
                Err(Error::Other)
            );
            assert_eq!(client.fault.borrow().count, 0);
            let mut rebooted = fido_authenticator::state::PersistentState::default();
            rebooted.load_if_not_initialised(client, &config).unwrap();
        });
    }
}

#[test]
fn credential_save_and_nonresident_error_cleanup_do_not_panic_when_storage_is_offline() {
    for assertion in [false, true] {
        for after in [false, true] {
            run(|client, _| {
                let mut auth = authenticator(client);
                let credential_id = if assertion {
                    Some(created_id(&make_credential(&mut auth, 7, false, false)))
                } else {
                    None
                };
                *client.fault.borrow_mut() = StorageFault {
                    target: Some(FaultTarget::StateWrite(1)),
                    after,
                    ..Default::default()
                };
                let response = if let Some(id) = credential_id {
                    allowlist_assertion(&mut auth, &id)
                } else {
                    make_credential(&mut auth, 7, false, false)
                };
                assert_eq!(response, [Error::Other as u8]);
                assert!(client.fault.borrow().offline);
                assert_latched(&mut auth, client);
            });
        }
    }
}

#[test]
fn invalid_credential_ids_cannot_hide_a_lazy_key_state_save_failure() {
    for exclude in [false, true] {
        for after in [false, true] {
            run(|client, _| {
                let mut auth = authenticator(client);
                *client.fault.borrow_mut() = StorageFault {
                    target: Some(FaultTarget::StateWrite(1)),
                    after,
                    ..Default::default()
                };
                let response = if exclude {
                    make_credential(&mut auth, 7, false, true)
                } else {
                    allowlist_assertion(&mut auth, &[0])
                };
                assert_eq!(response, [Error::Other as u8]);
                assert!(client.fault.borrow().offline);
                assert_latched(&mut auth, client);
            });
        }
        // Ordinary unrecognized credential IDs retain their existing behavior.
        run(|client, _| {
            let mut auth = authenticator(client);
            if exclude {
                assert_eq!(make_credential(&mut auth, 7, false, true)[0], 0);
            } else {
                assert_eq!(
                    allowlist_assertion(&mut auth, &[0]),
                    [Error::NoCredentials as u8]
                );
            }
        });
    }
}

#[test]
fn reset_removes_orphan_replacement_files_and_preserves_attestation_after_failures() {
    use trussed::{
        key::{Flags, Key, Kind},
        platform::Platform as _,
        store::Store as _,
    };
    use trussed_core::{
        CertificateClient, FilesystemClient,
        types::{CertId, KeyId, Mechanism},
    };
    // This synthetic test identity has no relationship to any device identity.
    let key = Key {
        flags: Flags::SENSITIVE,
        kind: Kind::P256,
        material: [1; 32].as_slice().try_into().unwrap(),
    }
    .serialize();
    let mut certificate = vec![
        0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04, 0x04, 0x12,
        0x04, 0x10,
    ];
    certificate.extend_from_slice(&[0xa5; 16]);
    let key_path = littlefs2_core::path!("fido/sec/00");
    let cert_path = littlefs2_core::path!("fido/x5c/00");
    for target in [
        None,
        Some(FaultTarget::RemoveFile(littlefs2_core::path!("rk-new"))),
        Some(FaultTarget::RemoveFile(littlefs2_core::path!(
            "rk-transaction-new"
        ))),
        Some(FaultTarget::DeleteAll(Location::Internal)),
        Some(FaultTarget::DeleteAll(Location::Volatile)),
    ] {
        for after in [false, true] {
            let directory = tempfile::Builder::new()
                .prefix("salpa-reset-fault-")
                .tempdir_in(std::env::var_os("TMPDIR").unwrap())
                .unwrap();
            let image = directory.path().join("internal.store");
            run_with_store_files(
                filesystem_store(&image),
                &[(key_path, key.as_slice()), (cert_path, &certificate)],
                |client, _| {
                    let mut auth = authenticator(client);
                    assert_eq!(make_resident(&mut auth, 7)[0], 0);
                    set_or_change_pin(client, &mut auth, PinProtocolVersion::V2, None, "reset-pin");
                    let token = grant(
                        client,
                        &mut auth,
                        PinProtocolVersion::V2,
                        "reset-pin",
                        4,
                        None,
                    )
                    .unwrap();
                    for path in [
                        littlefs2_core::path!("rk-new"),
                        littlefs2_core::path!("rk-transaction-new"),
                    ] {
                        syscall!(client.write_file(
                            Location::Internal,
                            path.into(),
                            b"synthetic-orphan".as_slice().try_into().unwrap(),
                            None,
                        ));
                    }
                    *client.fault.borrow_mut() = StorageFault {
                        target,
                        after,
                        ..Default::default()
                    };
                    let response = command(&mut auth, &[7]);
                    if target.is_some() {
                        assert_eq!(response, [Error::Other as u8]);
                        assert!(client.fault.borrow().offline);
                        let sig = signature(&token, PinProtocolVersion::V2, &[1]);
                        assert_eq!(
                            metadata(&mut auth, PinProtocolVersion::V2, &sig),
                            Error::Other as u8
                        );
                        assert_latched(&mut auth, client);
                    } else {
                        assert_eq!(response, [0]);
                    }
                },
            );
            // Resume with fresh physical approval in a fresh virtual runtime.
            run_with_store(filesystem_store(&image), |client, _| {
                let mut auth = reopen(client);
                assert_eq!(command(&mut auth, &[7]), [0]);
                for path in [
                    littlefs2_core::path!("rk-new"),
                    littlefs2_core::path!("rk-transaction-new"),
                    littlefs2_core::path!("rk-transaction"),
                    littlefs2_core::path!("rk"),
                ] {
                    assert!(
                        syscall!(client.entry_metadata(Location::Internal, path.into()))
                            .metadata
                            .is_none()
                    );
                }
                assert_eq!(resident_assertion(&mut auth), [Error::NoCredentials as u8]);
                let info = command(&mut auth, &[4]);
                let info: ctap_types::ctap2::get_info::Response =
                    cbor_smol::cbor_deserialize(&info[1..]).unwrap();
                assert_eq!(info.options.unwrap().client_pin, Some(false));
                assert_eq!(info.aaguid.as_slice(), &[0xa5; 16]);
                assert!(syscall!(client.exists(Mechanism::P256, KeyId::from_special(0))).exists);
                assert_eq!(
                    syscall!(client.read_certificate(CertId::from_special(0)))
                        .der
                        .as_slice(),
                    certificate
                );
            });
            virt::with_platform(filesystem_store(&image), |platform| {
                assert_eq!(
                    platform
                        .store()
                        .ifs()
                        .read::<heapless_bytes::Bytes<64>>(key_path)
                        .unwrap()
                        .as_slice(),
                    key.as_slice()
                );
                assert_eq!(
                    platform
                        .store()
                        .ifs()
                        .read::<heapless_bytes::Bytes<64>>(cert_path)
                        .unwrap()
                        .as_slice(),
                    certificate
                );
            });
        }
    }
}

#[test]
fn resident_replacement_survives_faults_before_and_after_each_storage_operation() {
    let mut operations = 0;
    let mut commit_operation = 0;
    run(|client, _| {
        let mut auth = authenticator(client);
        assert_eq!(make_resident(&mut auth, 7)[0], 0);
        client.fault.borrow_mut().count = 0;
        assert_eq!(make_resident(&mut auth, 7)[0], 0);
        operations = client.fault.borrow().count;
        commit_operation = client.fault.borrow().commit_operation.unwrap();
    });
    assert!(operations >= 8);
    eprintln!("resident replacement: {operations} mutation boundaries, before and after each");
    for at in 1..=operations {
        for after in [false, true] {
            let root = std::env::var_os("TMPDIR").unwrap();
            let directory = tempfile::Builder::new()
                .prefix("salpa-rk-fault-")
                .tempdir_in(root)
                .unwrap();
            let image = directory.path().join("internal.store");
            let store = || {
                let mut config = StoreConfig::ram();
                config.internal = virt::StorageConfig::filesystem(image.clone());
                config
            };
            let mut old_id = Vec::new();
            let mut new_id = None;
            run_with_store(store(), |client, _| {
                let mut auth = authenticator(client);
                old_id = created_id(&make_resident(&mut auth, 7));
                *client.fault.borrow_mut() = StorageFault {
                    at: Some(at),
                    after,
                    ..Default::default()
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    make_resident(&mut auth, 7)
                }));
                if let Ok(response) = result {
                    if response[0] == 0 {
                        new_id = Some(created_id(&response));
                    }
                }
                assert!(client.fault.borrow().offline, "fault {at} was not reached");
            });
            // Reopen the actual persisted LittleFS image in a fresh platform/client.
            run_with_store(store(), |client, _| {
                let mut auth = reopen(client);
                let response = resident_assertion(&mut auth);
                assert_eq!(
                    response[0], 0,
                    "lost credential at operation {at}, after={after}"
                );
                let response: ctap_types::ctap2::get_assertion::Response =
                    cbor_smol::cbor_deserialize(&response[1..]).unwrap();
                assert!(!response.signature.is_empty());
                let committed = at > commit_operation || (at == commit_operation && after);
                assert_eq!(
                    response.credential.id.as_slice() != old_id.as_slice(),
                    committed,
                    "wrong credential recovered at operation {at}, after={after}"
                );
                assert!(
                    response.number_of_credentials.is_none(),
                    "duplicate credentials after recovery"
                );
                if let Some(new_id) = new_id.as_ref() {
                    assert_eq!(response.credential.id.as_slice(), new_id.as_slice());
                }
                // A second replacement must also work after recovery.
                let final_id = created_id(&make_resident(&mut auth, 7));
                assert_ne!(final_id, old_id);
                let response = resident_assertion(&mut auth);
                assert_eq!(response[0], 0);
            });
        }
    }
}

#[test]
fn assertion_continuation_timeout_also_applies_after_pin_authorization() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        run(|client, clock| {
            let mut auth = authenticator(client);
            for user in 0..2 {
                assert_eq!(make_resident(&mut auth, user)[0], 0);
            }
            set_or_change_pin(client, &mut auth, version, None, "synthetic-pin");
            for (elapsed, status) in [(29_999, 0), (31_000, Error::NotAllowed as u8)] {
                clock.set(100_000);
                let token = grant(
                    client,
                    &mut auth,
                    version,
                    "synthetic-pin",
                    2,
                    Some("example.com"),
                )
                .unwrap();
                let sig = signature(&token, version, &[0x43; 32]);
                let mut request = b"\x02\xa4\x01\x6bexample.com\x02\x58\x20".to_vec();
                request.extend_from_slice(&[0x43; 32]);
                request.push(6);
                if sig.len() < 24 {
                    request.push(0x40 + sig.len() as u8);
                } else {
                    request.extend_from_slice(&[0x58, sig.len() as u8]);
                }
                request.extend_from_slice(&sig);
                request.extend_from_slice(&[7, u8::from(version)]);
                assert_eq!(command(&mut auth, &request)[0], 0);
                clock.set(100_000 + elapsed);
                assert_eq!(command(&mut auth, &[8])[0], status);
            }
        });
    }
}

#[test]
fn replacement_at_the_credential_limit_preserves_the_new_key_on_rejected_addition() {
    run(|client, _| {
        drop(authenticator(client));
        let mut config = super::config::fido_config();
        config.max_resident_credential_count = Some(1);
        let mut auth = reopen_with_config(client, config);
        let old = created_id(&make_resident(&mut auth, 7));
        let new = created_id(&make_resident(&mut auth, 7));
        assert_ne!(old, new);
        assert_eq!(make_resident(&mut auth, 8)[0], Error::KeyStoreFull as u8);
        drop(auth);
        let mut auth = reopen_with_config(client, config);
        let response = resident_assertion(&mut auth);
        assert_eq!(response[0], 0);
        let response: ctap_types::ctap2::get_assertion::Response =
            cbor_smol::cbor_deserialize(&response[1..]).unwrap();
        assert_eq!(response.credential.id.as_slice(), new.as_slice());
    });
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() < 24 {
        out.push(0x40 + bytes.len() as u8);
    } else if bytes.len() < 256 {
        out.extend_from_slice(&[0x58, bytes.len() as u8]);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn cm_rp_parameters() -> Vec<u8> {
    use sha2::Digest;
    let mut parameters = vec![0xa1, 1];
    cbor_bytes(&mut parameters, &Sha256::digest(b"example.com"));
    parameters
}

fn cm_credential_parameters(id: &[u8], user: Option<u8>) -> Vec<u8> {
    let mut parameters = vec![if user.is_some() { 0xa2 } else { 0xa1 }, 2];
    parameters.extend_from_slice(b"\xa2\x62id");
    cbor_bytes(&mut parameters, id);
    parameters.extend_from_slice(b"\x64type\x6apublic-key");
    if let Some(user) = user {
        parameters.extend_from_slice(b"\x03\xa3\x62id\x41");
        parameters.push(user);
        parameters.extend_from_slice(b"\x64name\x67updated\x6bdisplayName\x67Updated");
    }
    parameters
}

fn management<C>(
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
    token: &[u8],
    sub: u8,
    parameters: Option<&[u8]>,
) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    let mut signed = vec![sub];
    if let Some(parameters) = parameters {
        signed.extend_from_slice(parameters);
    }
    let sig = signature(token, version, &signed);
    let mut request = vec![0x0a, if parameters.is_some() { 0xa4 } else { 0xa3 }, 1, sub];
    if let Some(parameters) = parameters {
        request.push(2);
        request.extend_from_slice(parameters);
    }
    request.extend_from_slice(&[3, u8::from(version), 4]);
    cbor_bytes(&mut request, &sig);
    command(auth, &request)
}

fn management_response(response: &[u8]) -> ctap_types::ctap2::credential_management::Response {
    assert_eq!(response[0], 0);
    cbor_smol::cbor_deserialize(&response[1..]).unwrap()
}

fn management_token<C: PollClient>(
    client: &mut ClockClient<C>,
    auth: &mut TestAuthenticator<C>,
    version: PinProtocolVersion,
) -> Vec<u8>
where
    ClockClient<C>: fido_authenticator::TrussedRequirements,
{
    set_or_change_pin(client, auth, version, None, "synthetic-pin");
    grant(client, auth, version, "synthetic-pin", 4, None).unwrap()
}

#[test]
fn credential_management_read_errors_clear_cursors_and_allow_a_fresh_retry() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        for sub in 1..=7 {
            let mut targets = vec![FaultTarget::ReadDirFirst, FaultTarget::ReadDirNext(1)];
            if sub != 1 {
                targets.push(FaultTarget::CredentialRead(1));
            }
            for target in targets {
                run(|client, _| {
                    let mut auth = authenticator(client);
                    let id = created_id(&make_resident(&mut auth, 7));
                    assert_eq!(make_resident(&mut auth, 8)[0], 0);
                    assert_eq!(
                        make_credential_for_rp(&mut auth, 9, true, false, "other.test")[0],
                        0
                    );
                    let token = management_token(client, &mut auth, version);
                    let rp = cm_rp_parameters();
                    assert_eq!(management(&mut auth, version, &token, 2, None)[0], 0);
                    assert_eq!(management(&mut auth, version, &token, 4, Some(&rp))[0], 0);
                    // A missing descriptor forces lookup to walk beyond the first
                    // entry; real IDs are used for targeted credential-file reads.
                    let descriptor = if matches!(target, FaultTarget::ReadDirNext(_)) {
                        &[0][..]
                    } else {
                        &id[..]
                    };
                    let credential = cm_credential_parameters(descriptor, (sub == 7).then_some(7));
                    let parameters = match sub {
                        4 => Some(rp.as_slice()),
                        6 | 7 => Some(credential.as_slice()),
                        _ => None,
                    };
                    *client.fault.borrow_mut() = StorageFault {
                        target: Some(target),
                        ..Default::default()
                    };
                    assert_eq!(
                        management(&mut auth, version, &token, sub, parameters),
                        [Error::Other as u8]
                    );
                    assert!(client.fault.borrow().offline);
                    // Restore I/O before the next dispatch. This tests a failed
                    // filesystem read, not unavailable PIN cleanup or uptime.
                    *client.fault.borrow_mut() = StorageFault::default();
                    assert_eq!(
                        management(&mut auth, version, &token, 3, None),
                        [Error::NotAllowed as u8]
                    );
                    assert_eq!(
                        management(&mut auth, version, &token, 5, None),
                        [Error::NotAllowed as u8]
                    );
                    let metadata =
                        management_response(&management(&mut auth, version, &token, 1, None));
                    assert_eq!(metadata.existing_resident_credentials_count, Some(3));
                    assert_eq!(management(&mut auth, version, &token, 2, None)[0], 0);
                    assert_eq!(management(&mut auth, version, &token, 3, None)[0], 0);
                    assert_eq!(management(&mut auth, version, &token, 4, Some(&rp))[0], 0);
                    assert_eq!(management(&mut auth, version, &token, 5, None)[0], 0);
                });
            }
        }
    }
}

#[test]
fn resident_lookup_read_errors_preserve_existing_credentials() {
    for target in [
        FaultTarget::ReadDirFirst,
        FaultTarget::ReadDirNext(1),
        FaultTarget::CredentialRead(1),
    ] {
        run(|client, _| {
            let mut auth = authenticator(client);
            let id = created_id(&make_resident(&mut auth, 7));
            *client.fault.borrow_mut() = StorageFault {
                target: Some(target),
                ..Default::default()
            };
            assert_eq!(make_resident(&mut auth, 8), [Error::Other as u8]);
            assert!(client.fault.borrow().offline);
            *client.fault.borrow_mut() = StorageFault::default();
            assert_eq!(allowlist_assertion(&mut auth, &id)[0], 0);
            assert_eq!(make_resident(&mut auth, 8)[0], 0);
        });
    }
}

fn assertion_response(response: &[u8]) -> ctap_types::ctap2::get_assertion::Response {
    assert_eq!(response[0], 0);
    cbor_smol::cbor_deserialize(&response[1..]).unwrap()
}

#[test]
fn discoverable_assertion_read_errors_end_without_a_continuation() {
    // With two discoverable credentials, building the cache reads rk files 1
    // and 2. Returning the first assertion reads one of them again (read 3).
    for target in [
        FaultTarget::ReadDirFirst,
        FaultTarget::ReadDirNext(1),
        FaultTarget::CredentialRead(1),
        FaultTarget::CredentialRead(2),
        FaultTarget::CredentialRead(3),
    ] {
        run(|client, _| {
            let mut auth = authenticator(client);
            assert_eq!(make_resident(&mut auth, 7)[0], 0);
            assert_eq!(make_resident(&mut auth, 8)[0], 0);
            *client.fault.borrow_mut() = StorageFault {
                target: Some(target),
                ..Default::default()
            };
            assert_eq!(resident_assertion(&mut auth), [Error::Other as u8]);
            assert!(client.fault.borrow().offline);
            // Restore I/O. A failed read is not a persistence failure, so the
            // runtime stays usable, but no partial cache may be continued.
            *client.fault.borrow_mut() = StorageFault::default();
            assert_eq!(command(&mut auth, &[8]), [Error::NotAllowed as u8]);
            let first = assertion_response(&resident_assertion(&mut auth));
            assert_eq!(first.number_of_credentials, Some(2));
            assert_eq!(command(&mut auth, &[8])[0], 0);
        });
    }
}

#[test]
fn next_assertion_read_error_ends_the_continuation() {
    run(|client, _| {
        let mut auth = authenticator(client);
        assert_eq!(make_resident(&mut auth, 7)[0], 0);
        assert_eq!(make_resident(&mut auth, 8)[0], 0);
        let first = assertion_response(&resident_assertion(&mut auth));
        assert_eq!(first.number_of_credentials, Some(2));
        // A fresh fault counter: the next rk read is GetNextAssertion's.
        *client.fault.borrow_mut() = StorageFault {
            target: Some(FaultTarget::CredentialRead(1)),
            ..Default::default()
        };
        assert_eq!(command(&mut auth, &[8]), [Error::Other as u8]);
        assert!(client.fault.borrow().offline);
        *client.fault.borrow_mut() = StorageFault::default();
        assert_eq!(command(&mut auth, &[8]), [Error::NotAllowed as u8]);
        let again = assertion_response(&resident_assertion(&mut auth));
        assert_eq!(again.number_of_credentials, Some(2));
        assert_eq!(command(&mut auth, &[8])[0], 0);
    });
}

#[test]
fn credential_management_mutations_discard_continuations_but_keep_the_pin_grant() {
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        for sub in [6, 7] {
            run(|client, _| {
                let mut auth = authenticator(client);
                let ids = [
                    created_id(&make_resident(&mut auth, 7)),
                    created_id(&make_resident(&mut auth, 8)),
                ];
                assert_eq!(
                    make_credential_for_rp(&mut auth, 9, true, false, "other.test")[0],
                    0
                );
                let token = management_token(client, &mut auth, version);
                let rp = cm_rp_parameters();
                assert_eq!(management(&mut auth, version, &token, 2, None)[0], 0);
                assert_eq!(management(&mut auth, version, &token, 4, Some(&rp))[0], 0);
                let first: ctap_types::ctap2::get_assertion::Response = {
                    // Avoid consuming the PIN grant's presence permissions;
                    // this host-only continuation requests no new user presence.
                    let mut request = b"\x02\xa3\x01\x6bexample.com\x02\x58\x20".to_vec();
                    request.extend_from_slice(&[0x43; 32]);
                    request.extend_from_slice(b"\x05\xa1\x62up\xf4");
                    let response = command(&mut auth, &request);
                    assert_eq!(response[0], 0);
                    cbor_smol::cbor_deserialize(&response[1..]).unwrap()
                };
                assert_eq!(first.number_of_credentials, Some(2));
                let pending = usize::from(first.credential.id.as_slice() == ids[0]);
                let parameters = cm_credential_parameters(
                    &ids[pending],
                    (sub == 7).then_some(7 + pending as u8),
                );
                let private_key = resident_private_key(client, 7 + pending as u8);
                assert_eq!(
                    management(&mut auth, version, &token, sub, Some(&parameters))[0],
                    0
                );
                assert_eq!(
                    syscall!(client.exists(trussed_core::types::Mechanism::P256, private_key))
                        .exists,
                    sub == 7
                );
                assert_eq!(command(&mut auth, &[8]), [Error::NotAllowed as u8]);
                assert_eq!(
                    management(&mut auth, version, &token, 3, None),
                    [Error::NotAllowed as u8]
                );
                assert_eq!(
                    management(&mut auth, version, &token, 5, None),
                    [Error::NotAllowed as u8]
                );
                let metadata =
                    management_response(&management(&mut auth, version, &token, 1, None));
                assert_eq!(
                    metadata.existing_resident_credentials_count,
                    Some(if sub == 6 { 2 } else { 3 })
                );
                if sub == 7 {
                    let response =
                        management_response(&management(&mut auth, version, &token, 4, Some(&rp)));
                    let response = if response.credential_id.unwrap().id.as_slice() == ids[pending]
                    {
                        response.user.unwrap()
                    } else {
                        management_response(&management(&mut auth, version, &token, 5, None))
                            .user
                            .unwrap()
                    };
                    assert_eq!(response.name.as_deref(), Some("updated"));
                }
                if sub == 6 {
                    assert_eq!(
                        allowlist_assertion(&mut auth, &ids[pending]),
                        [Error::NoCredentials as u8]
                    );
                }
                assert_eq!(allowlist_assertion(&mut auth, &ids[1 - pending])[0], 0);
            });
        }
    }
}

#[test]
fn credential_management_empty_store_and_missing_credentials_keep_their_status() {
    run(|client, _| {
        let mut auth = authenticator(client);
        let version = PinProtocolVersion::V2;
        let token = management_token(client, &mut auth, version);
        let metadata = management_response(&management(&mut auth, version, &token, 1, None));
        assert_eq!(metadata.existing_resident_credentials_count, Some(0));
        let rps = management_response(&management(&mut auth, version, &token, 2, None));
        assert_eq!(rps.total_rps, Some(0));
        assert_eq!(
            management(&mut auth, version, &token, 4, Some(&cm_rp_parameters())),
            [Error::NoCredentials as u8]
        );
        assert_eq!(
            management(
                &mut auth,
                version,
                &token,
                6,
                Some(&cm_credential_parameters(&[0], None))
            ),
            [Error::InvalidCredential as u8]
        );
        assert_eq!(
            management(
                &mut auth,
                version,
                &token,
                7,
                Some(&cm_credential_parameters(&[0], Some(7)))
            ),
            [Error::NoCredentials as u8]
        );
    });
    run(|client, _| {
        let mut auth = authenticator(client);
        let id = created_id(&make_resident(&mut auth, 7));
        let version = PinProtocolVersion::V2;
        let token = management_token(client, &mut auth, version);
        *client.fault.borrow_mut() = StorageFault::default();
        assert_eq!(
            management(
                &mut auth,
                version,
                &token,
                7,
                Some(&cm_credential_parameters(&id, Some(99)))
            ),
            [Error::InvalidParameter as u8]
        );
        assert_eq!(client.fault.borrow().count, 0);
        assert_eq!(
            management_response(&management(&mut auth, version, &token, 1, None))
                .existing_resident_credentials_count,
            Some(1)
        );
        assert_eq!(allowlist_assertion(&mut auth, &id)[0], 0);
    });
}

fn resident_private_key<C: PollClient>(
    client: &mut ClockClient<C>,
    user: u8,
) -> trussed_core::types::KeyId {
    use fido_authenticator::credential::{FullCredential, Key};
    use trussed_core::FilesystemClient;
    let mut next = syscall!(client.read_dir_first(
        Location::Internal,
        littlefs2_core::path!("rk").into(),
        None
    ))
    .entry;
    while let Some(entry) = next {
        let record = syscall!(client.read_file(Location::Internal, entry.path().into())).data;
        let credential = FullCredential::deserialize(&record).unwrap();
        if credential.user.id().as_slice() == [user] {
            if let Key::ResidentKey(key) = credential.key {
                return key;
            }
        }
        next = syscall!(client.read_dir_next()).entry;
    }
    panic!("synthetic resident credential missing")
}

#[test]
fn credential_management_mutation_errors_latch_and_reopen_only_committed_records() {
    use trussed::{
        key::{Flags, Key, Kind},
        platform::Platform as _,
        store::Store as _,
    };
    let key_path = littlefs2_core::path!("fido/sec/00");
    let cert_path = littlefs2_core::path!("fido/x5c/00");
    // Synthetic special-ID identity, unrelated to all physical device identities.
    let attestation_key = Key {
        flags: Flags::SENSITIVE,
        kind: Kind::P256,
        material: [1; 32].as_slice().try_into().unwrap(),
    }
    .serialize();
    let mut certificate = vec![
        0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04, 0x04, 0x12,
        0x04, 0x10,
    ];
    certificate.extend_from_slice(&[0xa5; 16]);
    for version in [PinProtocolVersion::V1, PinProtocolVersion::V2] {
        for sub in [6, 7] {
            for at in 1..=if sub == 6 { 2 } else { 1 } {
                for false_delete in [false, true] {
                    if false_delete && (sub != 6 || at != 2) {
                        continue;
                    }
                    for after in [false, true] {
                        let directory = tempfile::Builder::new()
                            .prefix("salpa-management-fault-")
                            .tempdir_in(std::env::var_os("TMPDIR").unwrap())
                            .unwrap();
                        let image = directory.path().join("internal.store");
                        let mut id = Vec::new();
                        let mut unaffected = Vec::new();
                        let mut private_key = None;
                        run_with_store_files(
                            filesystem_store(&image),
                            &[(key_path, &attestation_key), (cert_path, &certificate)],
                            |client, _| {
                                let mut auth = authenticator(client);
                                id = created_id(&make_resident(&mut auth, 7));
                                unaffected = created_id(&make_resident(&mut auth, 8));
                                private_key = Some(resident_private_key(client, 7));
                                let token = management_token(client, &mut auth, version);
                                let parameters =
                                    cm_credential_parameters(&id, (sub == 7).then_some(7));
                                *client.fault.borrow_mut() = StorageFault {
                                    at: Some(at),
                                    after,
                                    false_delete,
                                    ..Default::default()
                                };
                                assert_eq!(
                                    management(&mut auth, version, &token, sub, Some(&parameters)),
                                    [if sub == 6 {
                                        Error::Other as u8
                                    } else {
                                        Error::KeyStoreFull as u8
                                    }]
                                );
                                assert!(client.fault.borrow().offline);
                                assert_latched(&mut auth, client);
                            },
                        );
                        run_with_store(filesystem_store(&image), |client, _| {
                            let mut auth = reopen(client);
                            assert_eq!(
                                syscall!(client.exists(
                                    trussed_core::types::Mechanism::P256,
                                    private_key.unwrap()
                                ))
                                .exists,
                                !(sub == 6 && at == 2 && after)
                            );
                            assert_eq!(allowlist_assertion(&mut auth, &unaffected)[0], 0);
                            let token = grant(client, &mut auth, version, "synthetic-pin", 4, None)
                                .unwrap();
                            let metadata = management_response(&management(
                                &mut auth, version, &token, 1, None,
                            ));
                            let removed = sub == 6 && (at > 1 || after);
                            assert_eq!(
                                metadata.existing_resident_credentials_count,
                                Some(if removed { 1 } else { 2 })
                            );
                            if sub == 7 {
                                let rp = cm_rp_parameters();
                                let response = management_response(&management(
                                    &mut auth,
                                    version,
                                    &token,
                                    4,
                                    Some(&rp),
                                ));
                                let user = if response.credential_id.unwrap().id.as_slice() == id {
                                    response.user.unwrap()
                                } else {
                                    management_response(&management(
                                        &mut auth, version, &token, 5, None,
                                    ))
                                    .user
                                    .unwrap()
                                };
                                assert_eq!(user.name.as_deref(), after.then_some("updated"));
                            }
                            assert_eq!(
                                allowlist_assertion(&mut auth, &id)[0],
                                if removed {
                                    Error::NoCredentials as u8
                                } else {
                                    0
                                }
                            );
                        });
                        virt::with_platform(filesystem_store(&image), |platform| {
                            for (path, expected) in [
                                (key_path, attestation_key.as_slice()),
                                (cert_path, certificate.as_slice()),
                            ] {
                                assert_eq!(
                                    platform
                                        .store()
                                        .ifs()
                                        .read::<heapless_bytes::Bytes<256>>(path)
                                        .unwrap()
                                        .as_slice(),
                                    expected
                                );
                            }
                        });
                    }
                }
            }
        }
    }
}

#[test]
fn persistent_key_rotation_errors_never_return_cached_keys_and_reopen_committed_references() {
    use fido_authenticator::{credential::CredentialIdVersion, state::PersistentState};
    use trussed_core::types::Mechanism;
    for version in [CredentialIdVersion::V1, CredentialIdVersion::V2] {
        for wrapping in [false, true] {
            for existing in [false, true] {
                for at in 1..=if existing { 3 } else { 2 } {
                    for false_delete in [false, true] {
                        if false_delete && (!existing || at != 3) {
                            continue;
                        }
                        for after in [false, true] {
                            let directory = tempfile::Builder::new()
                                .prefix("salpa-key-rotation-fault-")
                                .tempdir_in(std::env::var_os("TMPDIR").unwrap())
                                .unwrap();
                            let image = directory.path().join("internal.store");
                            let mut old = None;
                            let mut unaffected = None;
                            run_with_store(filesystem_store(&image), |client, _| {
                                drop(authenticator(client));
                                let mut config = fido_authenticator::Config::new(1024);
                                config.credential_id_version = Some(version);
                                let mut state = PersistentState::default();
                                state.load_if_not_initialised(client, &config).unwrap();
                                state.reset(client, &config).unwrap();
                                unaffected = Some(if wrapping {
                                    state.key_encryption_key(client).unwrap().0
                                } else {
                                    state.key_wrapping_key(client).unwrap().0
                                });
                                if existing {
                                    old = Some(if wrapping {
                                        state.key_wrapping_key(client).unwrap().0
                                    } else {
                                        state.key_encryption_key(client).unwrap().0
                                    });
                                }
                                *client.fault.borrow_mut() = StorageFault {
                                    at: Some(at),
                                    after,
                                    false_delete,
                                    ..Default::default()
                                };
                                let result = if wrapping {
                                    state.rotate_key_wrapping_key(client).map(|key| key.0)
                                } else {
                                    state.rotate_key_encryption_key(client).map(|key| key.0)
                                };
                                assert_eq!(result, Err(Error::Other));
                                assert!(client.fault.borrow().offline);
                                *client.fault.borrow_mut() = StorageFault::default();
                                assert_eq!(
                                    state.key_encryption_key(client).map(|key| key.0),
                                    Err(Error::Other)
                                );
                                assert_eq!(
                                    state.key_wrapping_key(client).map(|key| key.0),
                                    Err(Error::Other)
                                );
                                assert_eq!(
                                    state.rotate_key_encryption_key(client).map(|key| key.0),
                                    Err(Error::Other)
                                );
                                assert_eq!(
                                    state.rotate_key_wrapping_key(client).map(|key| key.0),
                                    Err(Error::Other)
                                );
                                assert_eq!(state.save(client), Err(Error::Other));
                                assert_eq!(client.fault.borrow().count, 0);
                            });
                            run_with_store(filesystem_store(&image), |client, _| {
                                let config = fido_authenticator::Config::new(1024);
                                let mut state = PersistentState::default();
                                state.load_if_not_initialised(client, &config).unwrap();
                                client.fault.borrow_mut().count = 0;
                                let key = if wrapping {
                                    state.key_wrapping_key(client).unwrap().0
                                } else {
                                    state.key_encryption_key(client).unwrap().0
                                };
                                let mechanism = match version {
                                    CredentialIdVersion::V1 => Mechanism::Chacha8Poly1305,
                                    CredentialIdVersion::V2 => Mechanism::Aes256Gcm,
                                };
                                // The symmetric mechanisms do not implement Exists.
                                // A real encryption proves the referenced key can be read.
                                let encrypted = syscall!(client.encrypt(
                                    mechanism,
                                    key,
                                    b"synthetic",
                                    b"",
                                    None
                                ));
                                assert!(!encrypted.ciphertext.is_empty());
                                let committed = at > 2 || (at == 2 && after);
                                assert_eq!(
                                    client.fault.borrow().count,
                                    if !existing && !committed { 2 } else { 0 }
                                );
                                if let Some(old) = old {
                                    assert_eq!(key != old, committed);
                                    assert_eq!(
                                        try_syscall!(client.encrypt(
                                            mechanism,
                                            old,
                                            b"synthetic",
                                            b"",
                                            None
                                        ))
                                        .is_ok(),
                                        !(at == 3 && after)
                                    );
                                }
                                let other = if wrapping {
                                    state.key_encryption_key(client).unwrap().0
                                } else {
                                    state.key_wrapping_key(client).unwrap().0
                                };
                                assert_eq!(Some(other), unaffected);
                                // Successful explicit rotation must publish the new key,
                                // remove the previous key, and retain the other key kind.
                                let next = if wrapping {
                                    state.rotate_key_wrapping_key(client).unwrap().0
                                } else {
                                    state.rotate_key_encryption_key(client).unwrap().0
                                };
                                assert_ne!(next, key);
                                assert!(
                                    try_syscall!(client.encrypt(
                                        mechanism,
                                        next,
                                        b"synthetic",
                                        b"",
                                        None
                                    ))
                                    .is_ok()
                                );
                                assert!(
                                    try_syscall!(client.encrypt(
                                        mechanism,
                                        key,
                                        b"synthetic",
                                        b"",
                                        None
                                    ))
                                    .is_err()
                                );
                                let stored = if wrapping {
                                    state.key_wrapping_key(client).unwrap().0
                                } else {
                                    state.key_encryption_key(client).unwrap().0
                                };
                                assert_eq!(stored, next);
                                let other_after = if wrapping {
                                    state.key_encryption_key(client).unwrap().0
                                } else {
                                    state.key_wrapping_key(client).unwrap().0
                                };
                                assert_eq!(other_after, other);
                                let mut auth = reopen(client);
                                let id = created_id(&make_credential(&mut auth, 7, false, false));
                                assert_eq!(allowlist_assertion(&mut auth, &id)[0], 0);
                            });
                        }
                    }
                }
            }
        }
    }
}
