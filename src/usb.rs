//! USB FIDO HID transport boundary.
//!
//! This module owns only USB device identity, HID descriptors, and fixed-size
//! report I/O. CTAPHID parsing and FIDO semantics belong above this boundary.

use usb_device::{
    UsbError,
    bus::{UsbBus, UsbBusAllocator},
    device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid},
    prelude::BuilderError,
};
use usbd_hid::{
    descriptor::{CtapReport, SerializedDescriptor},
    hid_class::HIDClass,
};

pub use crate::usb_identity::{IdentityError, UsbIdentity};

pub const REPORT_SIZE: usize = 64;
pub const POLL_INTERVAL_MS: u8 = 5;
pub const MANUFACTURER: &str = "Rissotek";
pub const PRODUCT: &str = "Salpa Security Key";

#[derive(Debug)]
pub enum BuildError {
    Descriptor(BuilderError),
}

impl From<BuilderError> for BuildError {
    fn from(error: BuilderError) -> Self {
        Self::Descriptor(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportError {
    Usb(UsbError),
    WrongSize(usize),
}

pub struct FidoUsb<'a, B: UsbBus> {
    device: UsbDevice<'a, B>,
    hid: HIDClass<'a, B>,
}

impl<'a, B: UsbBus> FidoUsb<'a, B> {
    pub fn new(
        allocator: &'a UsbBusAllocator<B>,
        identity: UsbIdentity<'a>,
    ) -> Result<Self, BuildError> {
        let hid = HIDClass::new(allocator, CtapReport::desc(), POLL_INTERVAL_MS);
        let strings = [StringDescriptors::default()
            .manufacturer(MANUFACTURER)
            .product(PRODUCT)
            .serial_number(identity.serial)];
        let device = UsbDeviceBuilder::new(allocator, UsbVidPid(identity.vid, identity.pid))
            .strings(&strings)?
            .max_packet_size_0(64)?
            .device_class(0)
            .device_sub_class(0)
            .device_protocol(0)
            .build();

        Ok(Self { device, hid })
    }

    pub fn poll(&mut self) -> bool {
        self.device.poll(&mut [&mut self.hid])
    }

    pub fn receive(&self, report: &mut [u8; REPORT_SIZE]) -> Result<bool, ReportError> {
        match self.hid.pull_raw_output(report) {
            Ok(REPORT_SIZE) => Ok(true),
            Ok(size) => Err(ReportError::WrongSize(size)),
            Err(UsbError::WouldBlock) => Ok(false),
            Err(error) => Err(ReportError::Usb(error)),
        }
    }

    pub fn send(&self, report: &[u8; REPORT_SIZE]) -> Result<(), ReportError> {
        match self.hid.push_raw_input(report) {
            Ok(REPORT_SIZE) => Ok(()),
            Ok(size) => Err(ReportError::WrongSize(size)),
            Err(error) => Err(ReportError::Usb(error)),
        }
    }
}
