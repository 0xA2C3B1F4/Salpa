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
use rissokey::platform::{attestation_import, flash_encryption};
use trussed::platform::UserInterface;
use trussed_core::{
    CertificateClient as _, CryptoClient as _, try_syscall,
    types::{CertId, KeyId, KeySerialization, Location, Mechanism, StorageAttributes},
};
use zeroize::{Zeroize as _, Zeroizing};

const ARMING_WINDOW: Duration = Duration::from_secs(30);
const REQUIRED_HOLD_MS: u64 = 5_000;
// Public binding files only. No private key is included in this executable.
const EXPECTED_CERTIFICATE: &[u8; 32] =
    include_bytes!(env!("RISSO_KEY_ATTESTATION_CERT_SHA256_FILE"));
const EXPECTED_PUBLIC_KEY: &[u8; 65] = include_bytes!(env!("RISSO_KEY_ATTESTATION_PUBLIC_FILE"));
const _: () =
    assert!(attestation_import::MAX_CERTIFICATE_BYTES <= trussed_core::config::MAX_MESSAGE_LENGTH);

esp_bootloader_esp_idf::esp_app_desc!();

struct ProvisioningUserInterface;

impl UserInterface for ProvisioningUserInterface {}

// Borrow one live hardware entropy source across two independent services.
// The proof service sees RAM for every Trussed storage location.
struct ImportPlatform<'a> {
    rng: &'a mut rissokey::platform::rng::HardwareRng,
    store: rissokey::platform::storage::FilesystemSet<'a>,
    ui: ProvisioningUserInterface,
}
impl<'a> trussed::Platform for ImportPlatform<'a> {
    type R = &'a mut rissokey::platform::rng::HardwareRng;
    type S = rissokey::platform::storage::FilesystemSet<'a>;
    type UI = ProvisioningUserInterface;
    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }
    fn store(&self) -> Self::S {
        self.store
    }
    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }
}
fn service<'a>(
    rng: &'a mut rissokey::platform::rng::HardwareRng,
    store: rissokey::platform::storage::FilesystemSet<'a>,
) -> trussed::Service<ImportPlatform<'a>, rissokey::platform::dispatch::FidoDispatch> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut service = trussed::Service::with_dispatch(
        ImportPlatform {
            rng,
            store,
            ui: ProvisioningUserInterface,
        },
        rissokey::platform::dispatch::FidoDispatch::default(),
    );
    service.set_seed_if_uninitialized(&seed);
    seed.zeroize();
    service
}

/// Import the explicitly selected development identity into initialized storage.
/// No format, fallback identity, USB command interface or eFuse changes.
#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    let button = Input::new(
        peripherals.GPIO16,
        InputConfig::default().with_pull(Pull::Up),
    );
    let mut led = Output::new(peripherals.GPIO15, Level::Low, OutputConfig::default());

    let started = Instant::now();
    let mut gesture = rissokey::platform::provisioning::ProvisioningGesture::new(REQUIRED_HOLD_MS);

    loop {
        let now = Instant::now();
        if now - started >= ARMING_WINDOW {
            signal_result(&mut led, 1);
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

    led.set_low();
    // The bounded plaintext buffer is zeroized before displaying any result.
    let mut payload = Zeroizing::new([0u8; attestation_import::STAGING_BYTES]);
    let result = (|| -> Result<(), u32> {
        flash_encryption::initialize().map_err(|_| 3u32)?;
        flash_encryption::read(attestation_import::STAGING_ADDRESS, &mut payload[..])
            .map_err(|_| 3u32)?;
        let identity =
            attestation_import::parse(&payload, EXPECTED_CERTIFICATE).map_err(|_| 4u32)?;
        if EXPECTED_PUBLIC_KEY[0] != 4 {
            return Err(4);
        }
        let mut storage = rissokey::platform::storage::FidoFlashStorage::new(peripherals.FLASH)
            .map_err(|_| 3u32)?;
        let mut internal_allocation = Allocation::new();
        let internal_filesystem =
            rissokey::platform::storage::mount_existing(&mut internal_allocation, &mut storage)
                .map_err(|_| 5u32)?;
        rissokey::platform::storage_init::verify_empty_identity_import_target(&internal_filesystem)
            .map_err(|_| 6u32)?;

        let mut volatile_storage = rissokey::platform::storage::VolatileStorage::new();
        Filesystem::format(&mut volatile_storage).expect("volatile FIDO storage format failed");
        let mut volatile_allocation = Allocation::new();
        let volatile_filesystem =
            Filesystem::mount(&mut volatile_allocation, &mut volatile_storage)
                .expect("volatile FIDO storage mount failed");
        let proof_store = rissokey::platform::storage::FilesystemSet::new(
            &volatile_filesystem,
            &volatile_filesystem,
        );

        let source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
        let mut hardware_rng = rissokey::platform::rng::HardwareRng::new(source)
            .expect("ESP hardware entropy source was not enabled");
        hardware_rng
            .startup_sanity_check()
            .expect("ESP hardware RNG failed startup sanity check");
        let proof_service = service(&mut hardware_rng, proof_store);

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
        let inline = rissokey::platform::runtime::InlineSyscall::new(proof_service, endpoint);
        let mut client = trussed::ClientImplementation::<
            _,
            rissokey::platform::dispatch::FidoDispatch,
        >::new(requester, inline, None);

        // Prove the scalar derives the independently expected public key before
        // committing an attestation key or certificate to persistent storage.
        let volatile_key = try_syscall!(client.unsafe_inject_key(
            Mechanism::P256,
            identity.key,
            Location::Volatile,
            KeySerialization::Raw
        ))
        .map_err(|_| 7u32)?
        .key;
        let public = try_syscall!(client.derive_key(
            Mechanism::P256,
            volatile_key,
            None,
            StorageAttributes::default().set_persistence(Location::Volatile)
        ))
        .map_err(|_| 7u32)?
        .key;
        let public_bytes =
            try_syscall!(client.serialize_key(Mechanism::P256, public, KeySerialization::Raw))
                .map_err(|_| 7u32)?
                .serialized_key;
        if public_bytes.as_slice() != &EXPECTED_PUBLIC_KEY[1..] {
            return Err(7);
        }
        try_syscall!(client.delete(public)).map_err(|_| 7u32)?;
        try_syscall!(client.delete(volatile_key)).map_err(|_| 7u32)?;
        drop(client);
        // Only a proven key/certificate binding can start persistent Trussed I/O.
        let persistent_store = rissokey::platform::storage::FilesystemSet::new(
            &internal_filesystem,
            &volatile_filesystem,
        );
        let persistent_service = service(&mut hardware_rng, persistent_store);
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
        let inline = rissokey::platform::runtime::InlineSyscall::new(persistent_service, endpoint);
        let mut client = trussed::ClientImplementation::<
            _,
            rissokey::platform::dispatch::FidoDispatch,
        >::new(requester, inline, None);

        let temporary_key = try_syscall!(client.unsafe_inject_key(
            Mechanism::P256,
            identity.key,
            Location::Internal,
            KeySerialization::Raw
        ))
        .map_err(|_| 8u32)?
        .key;
        let temporary_cert =
            try_syscall!(client.write_certificate(Location::Internal, identity.certificate))
                .map_err(|_| 8u32)?
                .id;

        let key_target = PathBuf::from(rissokey::platform::attestation::ATTESTATION_KEY_PATH);
        let cert_target = PathBuf::from(rissokey::platform::attestation::ATTESTATION_CERT_PATH);
        if internal_filesystem.exists(&key_target) || internal_filesystem.exists(&cert_target) {
            return Err(6);
        }
        internal_filesystem
            .rename(&key_path(temporary_key), &key_target)
            .map_err(|_| 8u32)?;
        internal_filesystem
            .rename(&cert_path(temporary_cert), &cert_target)
            .map_err(|_| 8u32)?;

        if !try_syscall!(client.exists(Mechanism::P256, KeyId::from_special(0)))
            .map_err(|_| 9u32)?
            .exists
        {
            return Err(9);
        }
        let installed_cert = try_syscall!(client.read_certificate(CertId::from_special(0)))
            .map_err(|_| 9u32)?
            .der;
        if installed_cert.as_slice() != identity.certificate {
            return Err(9);
        }
        rissokey::platform::attestation::verify_development_attestation(&internal_filesystem)
            .map_err(|_| 9u32)?;
        // Only the staging sector is erased. Existing FIDO storage is not formatted.
        flash_encryption::erase(
            attestation_import::STAGING_ADDRESS,
            attestation_import::STAGING_BYTES,
        )
        .map_err(|_| 10u32)?;
        Ok(())
    })();
    payload.zeroize();
    signal_result(&mut led, result.err().unwrap_or(2));
}

fn signal_result(led: &mut Output<'_>, pulses: u32) -> ! {
    fn wait(ms: u64) {
        let start = Instant::now();
        while Instant::now() - start < Duration::from_millis(ms) {
            core::hint::spin_loop();
        }
    }
    loop {
        led.set_low();
        wait(2_000);
        for _ in 0..pulses {
            led.set_high();
            wait(250);
            led.set_low();
            wait(250);
        }
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
