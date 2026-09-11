//! Cooperative USB polling used while Trussed waits for user presence.

use core::cell::{Cell, RefCell};

use esp_hal::time::Instant;
use trussed_core::InterruptFlag;
use usb_device::{UsbError, bus::UsbBus};

use crate::{
    ctaphid::{CtapHid, Event, KeepaliveStatus, MAX_MESSAGE_SIZE, ReplyError},
    usb::{FidoUsb, REPORT_SIZE, ReportError},
};

use super::s2_user_presence::UserPresenceWaitHook;

pub const KEEPALIVE_INTERVAL_MS: u32 = 100;

pub struct UsbRuntime<'usb, B: UsbBus> {
    usb: RefCell<FidoUsb<'usb, B>>,
    ctaphid: RefCell<CtapHid<MAX_MESSAGE_SIZE>>,
    interrupt: Option<&'static InterruptFlag>,
    started: Instant,
    last_keepalive_ms: Cell<u32>,
    presence_cancelled: Cell<bool>,
}

impl<'usb, B: UsbBus> UsbRuntime<'usb, B> {
    pub fn new(
        usb: FidoUsb<'usb, B>,
        ctaphid: CtapHid<MAX_MESSAGE_SIZE>,
        interrupt: Option<&'static InterruptFlag>,
    ) -> Self {
        let started = Instant::now();
        Self {
            usb: RefCell::new(usb),
            ctaphid: RefCell::new(ctaphid),
            interrupt,
            started,
            last_keepalive_ms: Cell::new(0),
            presence_cancelled: Cell::new(false),
        }
    }

    pub fn poll(&self) -> Event {
        self.poll_at(self.now_ms())
    }

    pub fn copy_request(&self, destination: &mut [u8; MAX_MESSAGE_SIZE]) -> Option<usize> {
        let ctaphid = self.ctaphid.borrow();
        let request = ctaphid.request_payload()?;
        destination[..request.len()].copy_from_slice(request);
        Some(request.len())
    }

    pub fn reply_cbor(&self, response: &[u8]) -> Result<(), ReplyError> {
        self.ctaphid.borrow_mut().reply_cbor(response)
    }

    pub fn reply_update(&self, response: &[u8]) -> Result<(), ReplyError> {
        self.ctaphid.borrow_mut().reply_update(response)
    }

    fn now_ms(&self) -> u32 {
        self.started.elapsed().as_millis() as u32
    }

    fn poll_at(&self, now_ms: u32) -> Event {
        let mut event = Event::None;
        if self.usb.borrow_mut().poll() {
            let mut report = [0_u8; REPORT_SIZE];
            match self.usb.borrow().receive(&mut report) {
                Ok(true) => {
                    let (received_event, interrupted) =
                        self.ctaphid.borrow_mut().ingest_report(&report, now_ms);
                    event = received_event;
                    if interrupted {
                        self.presence_cancelled.set(true);
                        if let Some(interrupt) = self.interrupt {
                            let _ = interrupt.interrupt();
                        }
                    }
                }
                Ok(false) => {}
                Err(_) => self.transport_error(),
            }
        }

        self.ctaphid.borrow_mut().expire(now_ms);
        if self.send_pending() {
            event
        } else {
            Event::None
        }
    }

    fn transport_error(&self) {
        self.ctaphid.borrow_mut().transport_error();
        self.presence_cancelled.set(true);
        if let Some(interrupt) = self.interrupt {
            let _ = interrupt.interrupt();
        }
    }

    fn send_pending(&self) -> bool {
        let Some(packet) = self.ctaphid.borrow().next_packet() else {
            return true;
        };
        match self.usb.borrow().send(&packet) {
            Ok(()) => self.ctaphid.borrow_mut().packet_sent(),
            Err(ReportError::Usb(UsbError::WouldBlock)) => {}
            Err(_) => {
                self.transport_error();
                return false;
            }
        }
        true
    }
}

impl<B: UsbBus> UserPresenceWaitHook for UsbRuntime<'_, B> {
    fn begin_wait(&self) {
        self.last_keepalive_ms.set(self.now_ms());
        self.presence_cancelled.set(false);
    }

    fn poll_wait(&self) {
        let now_ms = self.now_ms();
        if now_ms.wrapping_sub(self.last_keepalive_ms.get()) >= KEEPALIVE_INTERVAL_MS {
            self.ctaphid
                .borrow_mut()
                .keepalive(KeepaliveStatus::UserPresenceNeeded);
            self.last_keepalive_ms.set(now_ms);
        }
        self.poll_at(now_ms);
    }

    fn cancelled(&self) -> bool {
        self.presence_cancelled.get()
    }
}
