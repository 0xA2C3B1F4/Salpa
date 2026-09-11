//! S2 FIDO startup and polling. Owners remain local for the lifetime of the runtime.

#[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
use super::USB_ENDPOINT_MEMORY;
#[cfg(feature = "signed-ab-update")]
use crate::ESP_APP_DESC;
use core::cell::RefCell;
#[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
use core::ptr::addr_of_mut;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
#[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
use esp_hal::otg_fs::{Usb, UsbBus};
use esp_hal::peripherals::Peripherals;
use littlefs2::fs::{Allocation, Filesystem};
use rand_core::RngCore as _;
use zeroize::Zeroize as _;

static FIDO_INTERRUPT: trussed_core::InterruptFlag = trussed_core::InterruptFlag::new();

// Keep storage, Trussed and USB borrows in the entry-point frame.
#[inline(always)]
#[allow(
    clippy::large_stack_frames,
    reason = "FIDO owns its storage and request buffers"
)]
pub(crate) fn run(peripherals: Peripherals) -> ! {
    let fido_config = salpa::config::fido_config();
    let mut hardware_rng = {
        let source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
        let mut rng = salpa::platform::rng::HardwareRng::new(source)
            .expect("ESP hardware entropy source was not enabled");
        rng.startup_sanity_check()
            .expect("ESP hardware RNG failed startup sanity check");
        rng
    };
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    let usb_identity = salpa::usb::UsbIdentity::from_build_values(
        env!("SALPA_USB_VID"),
        env!("SALPA_USB_PID"),
        env!("SALPA_USB_SERIAL"),
    )
    .expect("invalid USB bring-up identity");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    firmware_log!("RISSO_STAGE: usb-identity-ready");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    let usb_peripheral = Usb::new(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    firmware_log!("RISSO_STAGE: usb-peripheral-ready");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    let usb_allocator = UsbBus::new(usb_peripheral, unsafe {
        &mut *addr_of_mut!(USB_ENDPOINT_MEMORY)
    });
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    firmware_log!("RISSO_STAGE: usb-bus-ready");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    let fido_usb = salpa::usb::FidoUsb::new(&usb_allocator, usb_identity)
        .expect("failed to create USB FIDO HID device");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    firmware_log!("RISSO_STAGE: hid-ready");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    let ctaphid = salpa::ctaphid::CtapHid::<{ salpa::ctaphid::MAX_MESSAGE_SIZE }>::new(
        salpa::ctaphid::DeviceVersion {
            major: 0,
            minor: 1,
            build: 0,
        },
        salpa::ctaphid::CAPABILITY_CBOR | salpa::ctaphid::CAPABILITY_NMSG,
    );
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    firmware_log!("RISSO_STAGE: ctaphid-ready");
    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    let usb_runtime =
        salpa::platform::usb_runtime::UsbRuntime::new(fido_usb, ctaphid, Some(&FIDO_INTERRUPT));
    let user_hardware = {
        #[cfg(feature = "non-strapping-user-presence")]
        let button = Input::new(
            peripherals.GPIO16,
            InputConfig::default().with_pull(Pull::Up),
        );
        #[cfg(not(feature = "non-strapping-user-presence"))]
        let button = Input::new(
            peripherals.GPIO0,
            InputConfig::default().with_pull(Pull::Up),
        );
        let led = Output::new(peripherals.GPIO15, Level::Low, OutputConfig::default());
        RefCell::new(salpa::platform::s2_user_presence::WemosS2MiniUserHardware::new(button, led))
    };
    let user_interface = {
        let wait_hook = {
            #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
            {
                Some(&usb_runtime as &dyn salpa::platform::s2_user_presence::UserPresenceWaitHook)
            }
            #[cfg(not(all(feature = "usb-bringup", feature = "ctaphid-bringup")))]
            {
                None
            }
        };
        salpa::platform::s2_user_presence::WemosS2MiniUserInterface::new(&user_hardware, wait_hook)
    };
    let mut fido_flash_storage = salpa::platform::storage::FidoFlashStorage::new(peripherals.FLASH)
        .expect("fido_store backend initialization failed");
    let mut internal_allocation = Allocation::new();
    let internal_filesystem =
        salpa::platform::storage::mount_existing(&mut internal_allocation, &mut fido_flash_storage)
            .expect("fido_store mount or version check failed; refusing to modify credentials");
    salpa::platform::attestation::verify_development_attestation(&internal_filesystem)
        .expect("missing or invalid development attestation; refusing fallback identity");
    let mut volatile_storage = salpa::platform::storage::VolatileStorage::new();
    Filesystem::format(&mut volatile_storage).expect("volatile FIDO storage format failed");
    let mut volatile_allocation = Allocation::new();
    let volatile_filesystem = Filesystem::mount(&mut volatile_allocation, &mut volatile_storage)
        .expect("volatile FIDO storage mount failed");
    let store =
        salpa::platform::storage::FilesystemSet::new(&internal_filesystem, &volatile_filesystem);
    let mut trussed_seed = [0_u8; 32];
    hardware_rng.fill_bytes(&mut trussed_seed);
    let platform = salpa::platform::runtime::EspPlatform::new(hardware_rng, store, user_interface);
    let mut trussed_service = trussed::Service::with_dispatch(
        platform,
        salpa::platform::dispatch::FidoDispatch::default(),
    );
    trussed_service.set_seed_if_uninitialized(&trussed_seed);
    trussed_seed.zeroize();
    let trussed_channel = trussed::pipe::TrussedChannel::new();
    let (trussed_requester, trussed_responder) = trussed_channel
        .split()
        .expect("failed to split Trussed request channel");
    let trussed_context = trussed::types::CoreContext::with_interrupt(
        littlefs2::path!("fido").into(),
        Some(&FIDO_INTERRUPT),
    );
    let trussed_endpoint = trussed::pipe::ServiceEndpoint::new(
        trussed_responder,
        trussed_context,
        &salpa::platform::dispatch::FIDO_BACKENDS,
    );
    let trussed_syscall =
        salpa::platform::runtime::InlineSyscall::new(trussed_service, trussed_endpoint);
    let trussed_client =
        trussed::ClientImplementation::<_, salpa::platform::dispatch::FidoDispatch>::new(
            trussed_requester,
            trussed_syscall,
            Some(&FIDO_INTERRUPT),
        );
    let mut fido_authenticator = fido_authenticator::Authenticator::new(
        trussed_client,
        fido_authenticator::Conforming {},
        fido_config,
    );
    #[cfg(feature = "usb-signed-update")]
    let mut usb_updater = salpa::usb_update::UsbUpdater::new(
        salpa::platform::usb_update::Esp32S2UpdateBackend::new(
            core::ptr::addr_of!(ESP_APP_DESC) as u32
        ),
        salpa::platform::usb_update::trusted_update_key_digest(),
        salpa::image_version::APP_VERSION,
        ESP_APP_DESC.secure_version(),
    );

    #[cfg(feature = "usb-bringup")]
    firmware_log!("RISSO_STAGE: fido-config-ready");

    #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
    {
        use ctaphid_dispatch::app::Command;
        use salpa::ctaphid::Event;
        use salpa::request_completion::{self, CborCompletion};

        let mut request = [0_u8; salpa::ctaphid::MAX_MESSAGE_SIZE];
        firmware_log!("RISSO_STAGE: poll-loop");
        loop {
            #[cfg(feature = "usb-signed-update")]
            usb_updater.poll();
            match usb_runtime.poll() {
                Event::Cbor { .. } => {
                    let request_len = usb_runtime
                        .copy_request(&mut request)
                        .expect("CBOR event without request payload");
                    let mut response =
                        heapless_bytes::Bytes::<{ salpa::ctaphid::MAX_MESSAGE_SIZE }>::new();
                    FIDO_INTERRUPT.set_working();
                    let result = ctaphid_dispatch::app::App::call(
                        &mut fido_authenticator,
                        Command::Cbor,
                        &request[..request_len],
                        response.as_mut_view(),
                    );
                    user_hardware.borrow_mut().finish_request();
                    request[..request_len].zeroize();
                    FIDO_INTERRUPT.set_idle();
                    let completion = request_completion::complete_cbor(
                        result.is_ok(),
                        response.as_mut_slice(),
                        |bytes| usb_runtime.reply_cbor(bytes),
                    )
                    .expect("CTAP2 response exceeds transport buffer");
                    match completion {
                        CborCompletion::Succeeded => {
                            #[cfg(feature = "signed-ab-update")]
                            if salpa::image_version::CONFIRM_SIGNED_UPDATE {
                                salpa::platform::ota::confirm_running_image(
                                    salpa::image_version::APP_VERSION,
                                    ESP_APP_DESC.secure_version(),
                                    core::ptr::addr_of!(ESP_APP_DESC) as u32,
                                )
                                .expect("signed A/B confirmation failed");
                            }
                        }
                        CborCompletion::Failed | CborCompletion::Interrupted => {}
                    }
                }
                Event::Update { .. } => {
                    #[cfg(feature = "usb-signed-update")]
                    {
                        let request_len = usb_runtime
                            .copy_request(&mut request)
                            .expect("update event without request payload");
                        let mut response = [0_u8; 64];
                        #[cfg(feature = "security-epoch-maintenance")]
                        let maintenance_len = salpa::platform::security_epoch_maintenance::handle(
                            &request[..request_len],
                            core::ptr::addr_of!(ESP_APP_DESC) as u32,
                            usb_updater.phase(),
                            &user_hardware,
                            &usb_runtime,
                            &mut response,
                        );
                        #[cfg(not(feature = "security-epoch-maintenance"))]
                        let maintenance_len: Option<usize> = None;
                        #[cfg(any(
                            feature = "security-epoch-preview",
                            feature = "security-epoch-maintenance"
                        ))]
                        let preview_len = salpa::platform::security_epoch_preview::handle(
                            &request[..request_len],
                            core::ptr::addr_of!(ESP_APP_DESC) as u32,
                            usb_updater.phase(),
                            &mut response,
                        );
                        #[cfg(not(any(
                            feature = "security-epoch-preview",
                            feature = "security-epoch-maintenance"
                        )))]
                        let preview_len: Option<usize> = None;
                        #[cfg(feature = "release-flash-encryption")]
                        let memory_len = (request[..request_len]
                            == [salpa::platform::memory_protection::REQUEST])
                        .then(|| salpa::platform::memory_protection::status(&mut response));
                        #[cfg(not(feature = "release-flash-encryption"))]
                        let memory_len: Option<usize> = None;
                        let mut response_len = if let Some(length) =
                            maintenance_len.or(preview_len).or(memory_len)
                        {
                            length
                        } else if request[..request_len]
                            == [salpa::platform::security_status::REQUEST]
                        {
                            salpa::platform::security_status::read(ESP_APP_DESC.secure_version())
                                .encode(&mut response)
                        } else {
                            usb_updater.handle(&request[..request_len], false, &mut response)
                        };
                        if response[0] == salpa::usb_update::StatusCode::UserPresenceRequired as u8
                            && salpa::platform::s2_user_presence::confirm_update_user_presence(
                                &user_hardware,
                                &usb_runtime,
                            )
                        {
                            response_len =
                                usb_updater.handle(&request[..request_len], true, &mut response);
                        }
                        request[..request_len].zeroize();
                        let completion = request_completion::complete_update(
                            &mut response[..response_len],
                            |bytes| usb_runtime.reply_update(bytes),
                        );
                        response.zeroize();
                        completion.expect("update response exceeds transport buffer");
                    }
                    #[cfg(not(feature = "usb-signed-update"))]
                    unreachable!("disabled update command was dispatched");
                }
                // Transport cancellation ends the current presence wait,
                // not a previously approved update session. The vendor
                // Abort operation explicitly drops that session; INIT
                // resynchronization likewise leaves it available within
                // its device-enforced idle and absolute deadlines.
                Event::None | Event::Cancelled { .. } => {}
            }
        }
    }

    #[cfg(not(all(feature = "usb-bringup", feature = "ctaphid-bringup")))]
    let _ = &mut fido_authenticator;
    #[cfg(all(feature = "usb-bringup", not(feature = "ctaphid-bringup")))]
    super::usb_bringup::run(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);
    #[cfg(not(feature = "usb-bringup"))]
    super::idle()
}
