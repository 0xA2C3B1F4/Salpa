//! ESP32-S2 button consent. GPIO16 is the protected input.

use core::{cell::RefCell, time::Duration};

use esp_hal::gpio::Input;
use esp_hal::{gpio::Output, time::Instant};
use trussed::{platform::UserInterface, types::ui};
use trussed_core::types::{consent, reboot};

use super::presence_gate::{Level, PresenceGate};

pub trait UserPresenceWaitHook {
    fn begin_wait(&self) {}
    fn poll_wait(&self) {}
    fn end_wait(&self) {}
    fn cancelled(&self) -> bool {
        false
    }
}

pub const UPDATE_USER_PRESENCE_TIMEOUT_MS: u32 = 15_000;

pub struct WemosS2MiniUserHardware {
    button: Input<'static>,
    led: Output<'static>,
    gate: Option<PresenceGate>,
}

impl WemosS2MiniUserHardware {
    pub fn new(button: Input<'static>, mut led: Output<'static>) -> Self {
        led.set_low();
        Self {
            button,
            led,
            gate: None,
        }
    }

    fn begin(&mut self, timeout_ms: u64, long_hold: bool) {
        self.gate = Some(PresenceGate::new(now_ms(), timeout_ms, long_hold));
        self.led.set_high();
    }

    fn end(&mut self) {
        self.gate = None;
        self.led.set_low();
    }

    /// Trussed's cancellation/timeout returns can skip restoring UI status.
    /// The CTAP boundary always discards the gesture, including on errors.
    pub fn finish_request(&mut self) {
        self.end();
    }

    fn poll(&mut self, cancelled: bool) -> Option<bool> {
        let now = now_ms();
        let sample = Some(if self.button.is_low() {
            Level::Pressed
        } else {
            Level::Released
        });
        let gate = self.gate.as_mut()?;
        let result = gate.poll(sample, now, cancelled);
        if gate.ready_for_action() {
            self.led.set_high();
        }
        result
    }
}

pub struct WemosS2MiniUserInterface<'a> {
    hardware: &'a RefCell<WemosS2MiniUserHardware>,
    status: ui::Status,
    wait_hook: Option<&'a dyn UserPresenceWaitHook>,
}

impl<'a> WemosS2MiniUserInterface<'a> {
    pub fn new(
        hardware: &'a RefCell<WemosS2MiniUserHardware>,
        wait_hook: Option<&'a dyn UserPresenceWaitHook>,
    ) -> Self {
        Self {
            hardware,
            status: ui::Status::Idle,
            wait_hook,
        }
    }
}

fn confirm(
    hardware: &RefCell<WemosS2MiniUserHardware>,
    hook: &dyn UserPresenceWaitHook,
    timeout_ms: u64,
    long_hold: bool,
) -> bool {
    hardware.borrow_mut().begin(timeout_ms, long_hold);
    hook.begin_wait();
    let confirmed = loop {
        hook.poll_wait();
        if let Some(result) = hardware.borrow_mut().poll(hook.cancelled()) {
            break result;
        }
    };
    hook.end_wait();
    hardware.borrow_mut().end();
    confirmed
}

pub fn confirm_update_user_presence(
    hardware: &RefCell<WemosS2MiniUserHardware>,
    hook: &dyn UserPresenceWaitHook,
) -> bool {
    confirm(
        hardware,
        hook,
        u64::from(UPDATE_USER_PRESENCE_TIMEOUT_MS),
        false,
    )
}

#[cfg(feature = "security-epoch-maintenance")]
pub fn confirm_maintenance_user_presence(
    hardware: &RefCell<WemosS2MiniUserHardware>,
    hook: &dyn UserPresenceWaitHook,
) -> bool {
    confirm(hardware, hook, 30_000, true)
}

impl UserInterface for WemosS2MiniUserInterface<'_> {
    fn check_user_presence(&mut self) -> consent::Level {
        if self.status != ui::Status::WaitingForUserPresence {
            return consent::Level::None;
        }
        let cancelled = self.wait_hook.is_some_and(|hook| hook.cancelled());
        if self.hardware.borrow_mut().poll(cancelled) == Some(true) {
            consent::Level::Normal
        } else {
            consent::Level::None
        }
    }

    fn set_status(&mut self, status: ui::Status) {
        let was_waiting = self.status == ui::Status::WaitingForUserPresence;
        let is_waiting = status == ui::Status::WaitingForUserPresence;
        if is_waiting {
            // Trussed supplies the command-specific timeout. This additional
            // bound matches the normal FIDO profile's 30-second consent limit.
            self.hardware.borrow_mut().begin(30_000, false);
            if let Some(hook) = self.wait_hook {
                hook.begin_wait();
            }
        } else if !is_waiting && was_waiting {
            self.hardware.borrow_mut().end();
            if let Some(hook) = self.wait_hook {
                hook.end_wait();
            }
        }
        self.status = status;
    }

    fn status(&self) -> ui::Status {
        if self.hardware.borrow().gate.is_none() {
            ui::Status::Idle
        } else {
            self.status
        }
    }

    fn refresh(&mut self) {
        if self.status == ui::Status::WaitingForUserPresence
            && let Some(hook) = self.wait_hook
        {
            hook.poll_wait();
        }
    }

    fn uptime(&mut self) -> Duration {
        uptime()
    }
    fn reboot(&mut self, _to: reboot::To) -> ! {
        esp_hal::system::software_reset()
    }
}

fn now_ms() -> u64 {
    uptime().as_millis() as u64
}
fn uptime() -> Duration {
    Duration::from_micros(Instant::now().duration_since_epoch().as_micros())
}
