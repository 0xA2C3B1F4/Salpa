//! Test the actual vendored PIN module with real Trussed crypto and a fake clock.
//! Only Uptime is intercepted. No production clock override or test-approval
//! feature is added to the authenticator or firmware.

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
    syscall,
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

#[derive(Default)]
struct StorageFault {
    count: usize,
    commit_operation: Option<usize>,
    at: Option<usize>,
    after: bool,
    offline: bool,
}

struct ClockClient<C> {
    fault: Rc<RefCell<StorageFault>>,
    fault_reply: bool,
    fail_after_reply: bool,
    inner: Rc<RefCell<C>>,
    clock: Clock,
    clock_reply: bool,
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
        let hit = mutation && fault.at == Some(fault.count);
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
                Poll::Ready(Err(trussed_core::Error::FilesystemWriteFailure))
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
    virt::with_platform(store, |platform| {
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
    assert!(client_pin(auth, &request).is_ok());
    secret.delete(client);
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
    use sha2::Digest;
    let (public, secret) = exchange(client, auth, version);
    let encrypted = secret.encrypt(client, &Sha256::digest(pin.as_bytes())[..16]);
    let mut request = pin_request(version, 9);
    request.key_agreement = Some(public);
    request.pin_hash_enc = Some((&encrypted[..]).into());
    request.permissions = Some(permissions);
    request.rp_id = rp;
    let result = client_pin(auth, &request).map(|response| {
        secret
            .decrypt(client, &response.pin_token.unwrap())
            .unwrap()
            .to_vec()
    });
    secret.delete(client);
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
    // Synthetic RP/user and ES256, resident credential requested.
    let mut request = vec![1, 0xa5, 1, 0x58, 32];
    request.extend_from_slice(&[0x42; 32]);
    request.extend_from_slice(b"\x02\xa1\x62id\x6bexample.com\x03\xa1\x62id\x41");
    request.push(user);
    request.extend_from_slice(b"\x04\x81\xa2\x63alg\x26\x64type\x6apublic-key\x07\xa1\x62rk\xf5");
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
