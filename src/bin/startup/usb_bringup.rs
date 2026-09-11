//! USB enumeration and CTAPHID/GetInfo bring-up without the S2 FIDO runtime.

use super::USB_ENDPOINT_MEMORY;
use core::ptr::addr_of_mut;
use esp_hal::otg_fs::{Usb, UsbBus};
use esp_hal::peripherals::{GPIO19, GPIO20, USB0};
#[cfg(feature = "ctaphid-bringup")]
use esp_hal::time::Instant;

#[inline(always)]
#[allow(
    clippy::large_stack_frames,
    reason = "USB bring-up owns its HID and CTAPHID buffers"
)]
pub(super) fn run(usb0: USB0<'static>, usb_dp: GPIO20<'static>, usb_dm: GPIO19<'static>) -> ! {
    let identity = salpa::usb::UsbIdentity::from_build_values(
        env!("SALPA_USB_VID"),
        env!("SALPA_USB_PID"),
        env!("SALPA_USB_SERIAL"),
    )
    .expect("invalid USB bring-up identity");
    firmware_log!("RISSO_STAGE: usb-identity-ready");

    // ESP32-S2/S3 internal full-speed PHY: GPIO20 is D+ and GPIO19 is D-.
    let usb = Usb::new(usb0, usb_dp, usb_dm);
    firmware_log!("RISSO_STAGE: usb-peripheral-ready");
    let allocator = UsbBus::new(usb, unsafe { &mut *addr_of_mut!(USB_ENDPOINT_MEMORY) });
    firmware_log!("RISSO_STAGE: usb-bus-ready");
    let mut fido_usb = salpa::usb::FidoUsb::new(&allocator, identity)
        .expect("failed to create USB FIDO HID device");
    firmware_log!("RISSO_STAGE: hid-ready");

    let mut report = [0_u8; salpa::usb::REPORT_SIZE];
    #[cfg(feature = "ctaphid-bringup")]
    let mut ctaphid = salpa::ctaphid::CtapHid::<{ salpa::ctaphid::MAX_MESSAGE_SIZE }>::new(
        salpa::ctaphid::DeviceVersion {
            major: 0,
            minor: 1,
            build: 0,
        },
        salpa::ctaphid::CAPABILITY_CBOR | salpa::ctaphid::CAPABILITY_NMSG,
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
                    if let salpa::ctaphid::Event::Cbor { .. } = ctaphid.ingest(&report, now_ms) {
                        let response = salpa::get_info::dispatch(
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
                    Err(salpa::usb::ReportError::Usb(usb_device::UsbError::WouldBlock)) => {}
                    Err(_) => panic!("failed to send USB FIDO HID IN report"),
                }
            }
        }
    }
}
