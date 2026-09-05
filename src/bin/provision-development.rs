#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    main,
    time::{Duration, Instant},
};
use littlefs2::{
    fs::{Allocation, Filesystem},
    path::PathBuf,
};
use rand_core::RngCore as _;
use trussed::platform::UserInterface;
use trussed_core::{
    CertificateClient as _, CryptoClient as _, syscall,
    types::{CertId, KeyId, KeySerialization, Location, Mechanism},
};
use zeroize::Zeroize as _;

const ARMING_WINDOW: Duration = Duration::from_secs(30);
const REQUIRED_HOLD_MS: u64 = 5_000;
const ATTESTATION_KEY: &[u8; 32] = include_bytes!(env!("RISSO_KEY_DEV_ATTESTATION_KEY"));
const ATTESTATION_CERT: &[u8] = include_bytes!(env!("RISSO_KEY_DEV_ATTESTATION_CERT"));

const _: () = assert!(ATTESTATION_CERT.len() <= trussed_core::config::MAX_MESSAGE_LENGTH);

esp_bootloader_esp_idf::esp_app_desc!();

struct ProvisioningUserInterface;

impl UserInterface for ProvisioningUserInterface {}

/// Destructively creates a fresh development FIDO store and installs the
/// compile-time development attestation identity.
///
/// This binary is excluded from normal builds. It requires a release followed
/// by a new continuous five-second BOOT-button hold before formatting flash.
#[main]
fn main() -> ! {
    assert!(
        rissokey::identity::is_valid_p256_scalar(ATTESTATION_KEY),
        "attestation key is not a valid P-256 scalar"
    );
    assert_eq!(
        rissokey::identity::certificate_aaguid(ATTESTATION_CERT),
        Some(rissokey::identity::DEVELOPMENT_AAGUID),
        "attestation certificate has the wrong or missing AAGUID"
    );

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    );
    let mut led = Output::new(peripherals.GPIO15, Level::Low, OutputConfig::default());

    esp_println::println!("RISSO_DEV_PROVISION: release button, then hold it for five seconds");
    let started = Instant::now();
    let mut gesture = rissokey::platform::provisioning::ProvisioningGesture::new(REQUIRED_HOLD_MS);

    loop {
        let now = Instant::now();
        if now - started >= ARMING_WINDOW {
            panic!("development provisioning timed out without a confirmed hold");
        }

        let pressed = button.is_low();
        if pressed {
            led.set_high();
        } else {
            led.set_low();
        }
        if gesture.sample(pressed, now.duration_since_epoch().as_millis()) {
            break;
        }
    }

    esp_println::println!("RISSO_DEV_PROVISION: confirmed; formatting fido_store");
    let mut storage = rissokey::platform::storage::FidoFlashStorage::new(peripherals.FLASH)
        .expect("fido_store backend initialization failed");
    Filesystem::format(&mut storage).expect("fido_store format failed");

    let mut internal_allocation = Allocation::new();
    let internal_filesystem = Filesystem::mount(&mut internal_allocation, &mut storage)
        .expect("fresh fido_store mount failed");
    rissokey::platform::storage::write_storage_version(&internal_filesystem)
        .expect("fido_store version marker write failed");

    let mut volatile_storage = rissokey::platform::storage::VolatileStorage::new();
    Filesystem::format(&mut volatile_storage).expect("volatile FIDO storage format failed");
    let mut volatile_allocation = Allocation::new();
    let volatile_filesystem = Filesystem::mount(&mut volatile_allocation, &mut volatile_storage)
        .expect("volatile FIDO storage mount failed");
    let store =
        rissokey::platform::storage::FilesystemSet::new(&internal_filesystem, &volatile_filesystem);

    let source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut hardware_rng = rissokey::platform::rng::HardwareRng::new(source)
        .expect("ESP hardware entropy source was not enabled");
    hardware_rng
        .startup_sanity_check()
        .expect("ESP hardware RNG failed startup sanity check");
    let mut trussed_seed = [0_u8; 32];
    hardware_rng.fill_bytes(&mut trussed_seed);

    let platform = rissokey::platform::runtime::EspPlatform::new(
        hardware_rng,
        store,
        ProvisioningUserInterface,
    );
    let mut service = trussed::Service::with_dispatch(
        platform,
        rissokey::platform::dispatch::FidoDispatch::default(),
    );
    service.set_seed_if_uninitialized(&trussed_seed);
    trussed_seed.zeroize();

    let channel = trussed::pipe::TrussedChannel::new();
    let (requester, responder) = channel
        .split()
        .expect("failed to split Trussed request channel");
    let context = trussed::types::CoreContext::new(littlefs2::path!("fido").into());
    let endpoint = trussed::pipe::ServiceEndpoint::new(
        responder,
        context,
        &rissokey::platform::dispatch::FIDO_BACKENDS,
    );
    let inline = rissokey::platform::runtime::InlineSyscall::new(service, endpoint);
    let mut client =
        trussed::ClientImplementation::<_, rissokey::platform::dispatch::FidoDispatch>::new(
            requester, inline, None,
        );

    let temporary_key = syscall!(client.unsafe_inject_key(
        Mechanism::P256,
        ATTESTATION_KEY,
        Location::Internal,
        KeySerialization::Raw,
    ))
    .key;
    let temporary_cert =
        syscall!(client.write_certificate(Location::Internal, ATTESTATION_CERT)).id;

    let key_target = PathBuf::from(rissokey::platform::attestation::ATTESTATION_KEY_PATH);
    let cert_target = PathBuf::from(rissokey::platform::attestation::ATTESTATION_CERT_PATH);
    assert!(!internal_filesystem.exists(&key_target));
    assert!(!internal_filesystem.exists(&cert_target));
    internal_filesystem
        .rename(&key_path(temporary_key), &key_target)
        .expect("failed to install special attestation key ID");
    internal_filesystem
        .rename(&cert_path(temporary_cert), &cert_target)
        .expect("failed to install special attestation certificate ID");

    assert!(syscall!(client.exists(Mechanism::P256, KeyId::from_special(0))).exists);
    let installed_cert = syscall!(client.read_certificate(CertId::from_special(0))).der;
    assert_eq!(installed_cert.as_slice(), ATTESTATION_CERT);
    rissokey::platform::attestation::verify_development_attestation(&internal_filesystem)
        .expect("installed development attestation did not verify");
    rissokey::platform::storage::write_persistent_state_initialization_marker(&internal_filesystem)
        .expect("persistent-state initialization marker write failed");

    esp_println::println!("RISSO_DEV_PROVISION: complete; flash normal firmware next");
    led.set_high();
    loop {
        core::hint::spin_loop();
    }
}

fn key_path(id: KeyId) -> PathBuf {
    let mut path = PathBuf::from(littlefs2::path!("fido/sec"));
    path.push(&id.legacy_hex_path());
    path
}

fn cert_path(id: CertId) -> PathBuf {
    let mut path = PathBuf::from(littlefs2::path!("fido/x5c"));
    path.push(&id.legacy_hex_path());
    path
}
