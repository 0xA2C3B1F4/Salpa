//! WEMOS S2 Mini physical user-presence interface.
//!
//! Development firmware uses the board's active-low GPIO0 BOOT button.
//! Protected firmware selects an external active-low button on GPIO16. The
//! built-in LED is GPIO15 and active high in both builds.

use core::{cell::RefCell, time::Duration};

use esp_hal::{
    gpio::{Input, Output},
    time::Instant,
};
use trussed::{platform::UserInterface, types::ui};
use trussed_core::types::{consent, reboot};

use super::user_presence::{DEFAULT_DEBOUNCE_MS, PresenceTracker};

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
}

impl WemosS2MiniUserHardware {
    pub fn new(button: Input<'static>, mut led: Output<'static>) -> Self {
        led.set_low();
        Self { button, led }
    }

    fn button_pressed(&self) -> bool {
        self.button.is_low()
    }

    fn set_waiting(&mut self, waiting: bool) {
        if waiting {
            self.led.set_high();
        } else {
            self.led.set_low();
        }
    }
}

pub struct WemosS2MiniUserInterface<'a> {
    hardware: &'a RefCell<WemosS2MiniUserHardware>,
    tracker: PresenceTracker,
    status: ui::Status,
    wait_hook: Option<&'a dyn UserPresenceWaitHook>,
}

impl<'a> WemosS2MiniUserInterface<'a> {
    pub fn new(
        hardware: &'a RefCell<WemosS2MiniUserHardware>,
        wait_hook: Option<&'a dyn UserPresenceWaitHook>,
    ) -> Self {
        let now_ms = uptime().as_millis() as u64;
        let tracker = PresenceTracker::new(
            hardware.borrow().button_pressed(),
            now_ms,
            DEFAULT_DEBOUNCE_MS,
        );
        Self {
            hardware,
            tracker,
            status: ui::Status::Idle,
            wait_hook,
        }
    }

    fn sample_button(&mut self) {
        self.tracker.sample(
            self.hardware.borrow().button_pressed(),
            uptime().as_millis() as u64,
        );
    }

    fn apply_led_status(&mut self) {
        self.hardware
            .borrow_mut()
            .set_waiting(self.status == ui::Status::WaitingForUserPresence);
    }
}

/// Require a release followed by a fresh debounced press while keeping the
/// CTAPHID transaction alive. Holding the button before the request is not an
/// approval.
pub fn confirm_update_user_presence(
    hardware: &RefCell<WemosS2MiniUserHardware>,
    wait_hook: &dyn UserPresenceWaitHook,
) -> bool {
    let started = uptime();
    let started_ms = started.as_millis() as u64;
    let mut tracker = PresenceTracker::new(
        hardware.borrow().button_pressed(),
        started_ms,
        DEFAULT_DEBOUNCE_MS,
    );
    tracker.begin_waiting();
    hardware.borrow_mut().set_waiting(true);
    wait_hook.begin_wait();

    let confirmed = loop {
        let now = uptime();
        tracker.sample(hardware.borrow().button_pressed(), now.as_millis() as u64);
        if tracker.take_confirmation() {
            break true;
        }
        if now.saturating_sub(started)
            >= Duration::from_millis(u64::from(UPDATE_USER_PRESENCE_TIMEOUT_MS))
        {
            break false;
        }
        wait_hook.poll_wait();
        if wait_hook.cancelled() {
            break false;
        }
    };

    wait_hook.end_wait();
    hardware.borrow_mut().set_waiting(false);
    confirmed
}

impl UserInterface for WemosS2MiniUserInterface<'_> {
    fn check_user_presence(&mut self) -> consent::Level {
        self.sample_button();
        if self.tracker.take_confirmation() {
            consent::Level::Normal
        } else {
            consent::Level::None
        }
    }

    fn set_status(&mut self, status: ui::Status) {
        self.sample_button();
        let was_waiting = self.status == ui::Status::WaitingForUserPresence;
        let is_waiting = status == ui::Status::WaitingForUserPresence;
        if is_waiting && !was_waiting {
            self.tracker.begin_waiting();
            if let Some(wait_hook) = self.wait_hook {
                wait_hook.begin_wait();
            }
        } else if !is_waiting && was_waiting {
            self.tracker.end_waiting();
            if let Some(wait_hook) = self.wait_hook {
                wait_hook.end_wait();
            }
        }
        self.status = status;
        self.apply_led_status();
    }

    fn status(&self) -> ui::Status {
        self.status
    }

    fn refresh(&mut self) {
        self.sample_button();
        if self.status == ui::Status::WaitingForUserPresence
            && let Some(wait_hook) = self.wait_hook
        {
            wait_hook.poll_wait();
        }
    }

    fn uptime(&mut self) -> Duration {
        uptime()
    }

    fn reboot(&mut self, _to: reboot::To) -> ! {
        esp_hal::system::software_reset()
    }
}

fn uptime() -> Duration {
    Duration::from_micros(Instant::now().duration_since_epoch().as_micros())
}
