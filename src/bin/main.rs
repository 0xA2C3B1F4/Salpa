#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is not safe for HAL values that own hardware resources"
)]
#![deny(clippy::large_stack_frames)]

#[cfg(feature = "attestation-import")]
compile_error!("attestation-import must use the separate import-attestation binary");

#[cfg(feature = "firmware-diagnostics")]
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::main;
#[cfg(all(
    feature = "usb-bringup",
    feature = "ctaphid-bringup",
    not(all(feature = "fido-stack", feature = "mcu-esp32s2"))
))]
use esp_hal::time::Instant;
#[cfg(not(feature = "usb-bringup"))]
use esp_hal::time::{Duration, Instant};
#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
use littlefs2::fs::{Allocation, Filesystem};
#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
use rand_core::RngCore as _;
#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
use zeroize::Zeroize as _;

#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
use core::cell::RefCell;
#[cfg(feature = "usb-bringup")]
use core::ptr::addr_of_mut;
#[cfg(feature = "usb-bringup")]
use esp_hal::otg_fs::{Usb, UsbBus};

#[cfg(feature = "usb-bringup")]
static mut USB_ENDPOINT_MEMORY: [u32; 1024] = [0; 1024];

#[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
static FIDO_INTERRUPT: trussed_core::InterruptFlag = trussed_core::InterruptFlag::new();

esp_bootloader_esp_idf::esp_app_desc!(
    rissokey::image_version::APP_VERSION,
    env!("CARGO_PKG_NAME"),
    esp_bootloader_esp_idf::BUILD_TIME,
    esp_bootloader_esp_idf::BUILD_DATE,
    esp_bootloader_esp_idf::ESP_IDF_COMPATIBLE_VERSION,
    esp_bootloader_esp_idf::MMU_PAGE_SIZE,
    0,
    u16::MAX,
    esp_bootloader_esp_idf::SECURE_VERSION
);

#[cfg(all(feature = "usb-bringup", feature = "firmware-diagnostics"))]
macro_rules! firmware_log {
    ($($argument:tt)*) => {
        esp_println::println!($($argument)*);
    };
}

#[cfg(all(feature = "usb-bringup", not(feature = "firmware-diagnostics")))]
macro_rules! firmware_log {
    ($($argument:tt)*) => {};
}

#[cfg(not(feature = "firmware-diagnostics"))]
#[panic_handler]
fn panic_without_diagnostics(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[allow(
    clippy::large_stack_frames,
    reason = "embedded entry points may need larger local buffers during bring-up"
)]
#[main]
fn main() -> ! {
    // Based on esp-generate 1.3.0 with ESP32-S2/S3 and esp-backtrace options.
    #[cfg(feature = "usb-bringup")]
    firmware_log!("RISSO_STAGE: entry");

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    #[cfg(feature = "usb-bringup")]
    firmware_log!("RISSO_STAGE: hal-ready");

    #[cfg(feature = "fido-stack")]
    let fido_config = rissokey::config::fido_config();
    #[cfg(feature = "fido-stack")]
    let mut hardware_rng = {
        let source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
        let mut rng = rissokey::platform::rng::HardwareRng::new(source)
            .expect("ESP hardware entropy source was not enabled");
        rng.startup_sanity_check()
            .expect("ESP hardware RNG failed startup sanity check");
        rng
    };
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    let usb_identity = rissokey::usb::UsbIdentity::from_build_values(
        env!("RISSO_KEY_USB_VID"),
        env!("RISSO_KEY_USB_PID"),
        env!("RISSO_KEY_USB_SERIAL"),
    )
    .expect("invalid USB bring-up identity");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    firmware_log!("RISSO_STAGE: usb-identity-ready");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    let usb_peripheral = Usb::new(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    firmware_log!("RISSO_STAGE: usb-peripheral-ready");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    let usb_allocator = UsbBus::new(usb_peripheral, unsafe {
        &mut *addr_of_mut!(USB_ENDPOINT_MEMORY)
    });
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    firmware_log!("RISSO_STAGE: usb-bus-ready");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    let fido_usb = rissokey::usb::FidoUsb::new(&usb_allocator, usb_identity)
        .expect("failed to create USB FIDO HID device");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    firmware_log!("RISSO_STAGE: hid-ready");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    let ctaphid = rissokey::ctaphid::CtapHid::<{ rissokey::ctaphid::MAX_MESSAGE_SIZE }>::new(
        rissokey::ctaphid::DeviceVersion {
            major: 0,
            minor: 1,
            build: 0,
        },
        rissokey::ctaphid::CAPABILITY_CBOR | rissokey::ctaphid::CAPABILITY_NMSG,
    );
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    firmware_log!("RISSO_STAGE: ctaphid-ready");
    #[cfg(all(
        feature = "fido-stack",
        feature = "mcu-esp32s2",
        feature = "usb-bringup",
        feature = "ctaphid-bringup"
    ))]
    let usb_runtime =
        rissokey::platform::usb_runtime::UsbRuntime::new(fido_usb, ctaphid, Some(&FIDO_INTERRUPT));
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
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
        RefCell::new(
            rissokey::platform::s2_user_presence::WemosS2MiniUserHardware::new(button, led),
        )
    };
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let user_interface = {
        let wait_hook = {
            #[cfg(all(feature = "usb-bringup", feature = "ctaphid-bringup"))]
            {
                Some(
                    &usb_runtime as &dyn rissokey::platform::s2_user_presence::UserPresenceWaitHook,
                )
            }
            #[cfg(not(all(feature = "usb-bringup", feature = "ctaphid-bringup")))]
            {
                None
            }
        };
        rissokey::platform::s2_user_presence::WemosS2MiniUserInterface::new(
            &user_hardware,
            wait_hook,
        )
    };
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut fido_flash_storage =
        rissokey::platform::storage::FidoFlashStorage::new(peripherals.FLASH)
            .expect("fido_store backend initialization failed");
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut internal_allocation = Allocation::new();
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let internal_filesystem = rissokey::platform::storage::mount_existing(
        &mut internal_allocation,
        &mut fido_flash_storage,
    )
    .expect("fido_store mount or version check failed; refusing to modify credentials");
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    rissokey::platform::attestation::verify_development_attestation(&internal_filesystem)
        .expect("missing or invalid development attestation; refusing fallback identity");
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut volatile_storage = rissokey::platform::storage::VolatileStorage::new();
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    Filesystem::format(&mut volatile_storage).expect("volatile FIDO storage format failed");
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut volatile_allocation = Allocation::new();
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let volatile_filesystem = Filesystem::mount(&mut volatile_allocation, &mut volatile_storage)
        .expect("volatile FIDO storage mount failed");
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let store =
        rissokey::platform::storage::FilesystemSet::new(&internal_filesystem, &volatile_filesystem);
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut trussed_seed = [0_u8; 32];
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    hardware_rng.fill_bytes(&mut trussed_seed);
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let platform =
        rissokey::platform::runtime::EspPlatform::new(hardware_rng, store, user_interface);
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut trussed_service = trussed::Service::with_dispatch(
        platform,
        rissokey::platform::dispatch::FidoDispatch::default(),
    );
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    trussed_service.set_seed_if_uninitialized(&trussed_seed);
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    trussed_seed.zeroize();
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let trussed_channel = trussed::pipe::TrussedChannel::new();
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let (trussed_requester, trussed_responder) = trussed_channel
        .split()
        .expect("failed to split Trussed request channel");
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let trussed_context = trussed::types::CoreContext::with_interrupt(
        littlefs2::path!("fido").into(),
        Some(&FIDO_INTERRUPT),
    );
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let trussed_endpoint = trussed::pipe::ServiceEndpoint::new(
        trussed_responder,
        trussed_context,
        &rissokey::platform::dispatch::FIDO_BACKENDS,
    );
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let trussed_syscall =
        rissokey::platform::runtime::InlineSyscall::new(trussed_service, trussed_endpoint);
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let trussed_client = trussed::ClientImplementation::<
        _,
        rissokey::platform::dispatch::FidoDispatch,
    >::new(trussed_requester, trussed_syscall, Some(&FIDO_INTERRUPT));
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
    let mut fido_authenticator = fido_authenticator::Authenticator::new(
        trussed_client,
        fido_authenticator::Conforming {},
        fido_config,
    );
    #[cfg(feature = "usb-signed-update")]
    let mut usb_updater = rissokey::usb_update::UsbUpdater::new(
        rissokey::platform::usb_update::Esp32S2UpdateBackend::new(),
        rissokey::platform::usb_update::trusted_update_key_digest(),
        rissokey::image_version::APP_VERSION,
        ESP_APP_DESC.secure_version(),
    );
    #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s3"))]
    let _ = (&mut hardware_rng, fido_config);
    #[cfg(all(feature = "usb-bringup", feature = "fido-stack"))]
    firmware_log!("RISSO_STAGE: fido-config-ready");
    #[cfg(all(feature = "usb-bringup", not(feature = "fido-stack")))]
    firmware_log!("RISSO_STAGE: fido-stack-disabled");

    #[cfg(feature = "usb-bringup")]
    {
        #[cfg(all(
            feature = "fido-stack",
            feature = "mcu-esp32s2",
            feature = "ctaphid-bringup"
        ))]
        {
            use ctaphid_dispatch::app::Command;
            use rissokey::ctaphid::Event;
            use rissokey::request_completion::{self, CborCompletion};

            let mut request = [0_u8; rissokey::ctaphid::MAX_MESSAGE_SIZE];
            firmware_log!("RISSO_STAGE: poll-loop");
            loop {
                match usb_runtime.poll().expect("USB FIDO runtime failed") {
                    Event::Cbor { .. } => {
                        let request_len = usb_runtime
                            .copy_request(&mut request)
                            .expect("CBOR event without request payload");
                        let mut response =
                            heapless_bytes::Bytes::<{ rissokey::ctaphid::MAX_MESSAGE_SIZE }>::new();
                        FIDO_INTERRUPT.set_working();
                        let result = ctaphid_dispatch::app::App::call(
                            &mut fido_authenticator,
                            Command::Cbor,
                            &request[..request_len],
                            response.as_mut_view(),
                        );
                        request[..request_len].zeroize();
                        FIDO_INTERRUPT.set_idle();
                        let completion = request_completion::complete_cbor(
                            result.is_ok(),
                            response.as_mut_slice(),
                            |bytes| usb_runtime.reply_cbor(bytes),
                        )
                        .expect("CTAP2 response exceeds transport buffer");
                        match completion {
                            CborCompletion::Succeeded =>
                            {
                                #[cfg(feature = "signed-ab-update")]
                                if rissokey::image_version::CONFIRM_SIGNED_UPDATE {
                                    rissokey::platform::ota::confirm_running_image(
                                        rissokey::image_version::APP_VERSION,
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
                            let mut response_len =
                                usb_updater.handle(&request[..request_len], false, &mut response);
                            if response[0]
                                == rissokey::usb_update::StatusCode::UserPresenceRequired as u8
                                && rissokey::platform::s2_user_presence::confirm_update_user_presence(
                                    &user_hardware,
                                    &usb_runtime,
                                )
                            {
                                response_len = usb_updater.handle(
                                    &request[..request_len],
                                    true,
                                    &mut response,
                                );
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
                    Event::None | Event::Cancelled { .. } => {}
                }
            }
        }

        #[cfg(not(all(
            feature = "fido-stack",
            feature = "mcu-esp32s2",
            feature = "ctaphid-bringup"
        )))]
        {
            let identity = rissokey::usb::UsbIdentity::from_build_values(
                env!("RISSO_KEY_USB_VID"),
                env!("RISSO_KEY_USB_PID"),
                env!("RISSO_KEY_USB_SERIAL"),
            )
            .expect("invalid USB bring-up identity");
            firmware_log!("RISSO_STAGE: usb-identity-ready");

            // ESP32-S2/S3 internal full-speed PHY: GPIO20 is D+ and GPIO19 is D-.
            let usb = Usb::new(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);
            firmware_log!("RISSO_STAGE: usb-peripheral-ready");
            let allocator = UsbBus::new(usb, unsafe { &mut *addr_of_mut!(USB_ENDPOINT_MEMORY) });
            firmware_log!("RISSO_STAGE: usb-bus-ready");
            let mut fido_usb = rissokey::usb::FidoUsb::new(&allocator, identity)
                .expect("failed to create USB FIDO HID device");
            firmware_log!("RISSO_STAGE: hid-ready");

            let mut report = [0_u8; rissokey::usb::REPORT_SIZE];
            #[cfg(feature = "ctaphid-bringup")]
            let mut ctaphid =
                rissokey::ctaphid::CtapHid::<{ rissokey::ctaphid::MAX_MESSAGE_SIZE }>::new(
                    rissokey::ctaphid::DeviceVersion {
                        major: 0,
                        minor: 1,
                        build: 0,
                    },
                    rissokey::ctaphid::CAPABILITY_CBOR | rissokey::ctaphid::CAPABILITY_NMSG,
                );
            #[cfg(feature = "ctaphid-bringup")]
            let started = Instant::now();
            #[cfg(feature = "ctaphid-bringup")]
            firmware_log!("RISSO_STAGE: ctaphid-ready");
            firmware_log!("RISSO_STAGE: poll-loop");

            loop {
                #[cfg(feature = "ctaphid-bringup")]
                let now_ms = started.elapsed().as_millis() as u32;

                if fido_usb.poll() {
                    match fido_usb.receive(&mut report) {
                        Ok(true) => {
                            #[cfg(feature = "ctaphid-bringup")]
                            if let rissokey::ctaphid::Event::Cbor { .. } =
                                ctaphid.ingest(&report, now_ms)
                            {
                                let response = rissokey::get_info::dispatch(
                                    ctaphid
                                        .request_payload()
                                        .expect("CBOR event without request payload"),
                                );
                                ctaphid
                                    .reply_cbor(&response)
                                    .expect("CTAP2 response exceeds transport buffer");
                            }
                        }
                        Ok(false) => {}
                        Err(_) => panic!("invalid USB FIDO HID OUT report"),
                    }
                }

                #[cfg(feature = "ctaphid-bringup")]
                {
                    ctaphid.expire(now_ms);
                    if let Some(packet) = ctaphid.next_packet() {
                        match fido_usb.send(&packet) {
                            Ok(()) => ctaphid.packet_sent(),
                            Err(rissokey::usb::ReportError::Usb(
                                usb_device::UsbError::WouldBlock,
                            )) => {}
                            Err(_) => panic!("failed to send USB FIDO HID IN report"),
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "usb-bringup"))]
    {
        #[cfg(all(feature = "fido-stack", feature = "mcu-esp32s2"))]
        let _ = &mut fido_authenticator;
        #[cfg(not(feature = "fido-stack"))]
        let _ = peripherals;
        idle()
    }
}

#[cfg(not(feature = "usb-bringup"))]
fn idle() -> ! {
    loop {
        let delay_start = Instant::now();
        while delay_start.elapsed() < Duration::from_millis(500) {}
    }
}
