//! Debounced, one-shot user-presence tracking.

pub const DEFAULT_DEBOUNCE_MS: u64 = 30;

/// Converts active-low button samples into one confirmation per armed request.
///
/// A request is armed immediately only when both the raw and debounced button
/// states are released. If the button was already held, it must first be
/// released and debounced before a later press can confirm the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresenceTracker {
    debounce_ms: u64,
    raw_pressed: bool,
    raw_since_ms: u64,
    stable_pressed: bool,
    waiting: bool,
    armed: bool,
    confirmation_pending: bool,
}

impl PresenceTracker {
    pub const fn new(initial_pressed: bool, now_ms: u64, debounce_ms: u64) -> Self {
        Self {
            debounce_ms,
            raw_pressed: initial_pressed,
            raw_since_ms: now_ms,
            stable_pressed: initial_pressed,
            waiting: false,
            armed: false,
            confirmation_pending: false,
        }
    }

    pub fn begin_waiting(&mut self) {
        self.waiting = true;
        self.confirmation_pending = false;
        self.armed = !self.raw_pressed && !self.stable_pressed;
    }

    pub fn end_waiting(&mut self) {
        self.waiting = false;
        self.armed = false;
        self.confirmation_pending = false;
    }

    pub fn sample(&mut self, pressed: bool, now_ms: u64) {
        if pressed != self.raw_pressed {
            self.raw_pressed = pressed;
            self.raw_since_ms = now_ms;
            return;
        }

        if pressed == self.stable_pressed
            || now_ms.saturating_sub(self.raw_since_ms) < self.debounce_ms
        {
            return;
        }

        self.stable_pressed = pressed;
        if !self.waiting {
            return;
        }

        if pressed {
            if self.armed {
                self.confirmation_pending = true;
                self.armed = false;
            }
        } else {
            self.armed = true;
        }
    }

    pub fn take_confirmation(&mut self) -> bool {
        let pending = self.confirmation_pending;
        self.confirmation_pending = false;
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::PresenceTracker;

    const DEBOUNCE_MS: u64 = 30;

    #[test]
    fn fresh_debounced_press_is_consumed_once() {
        let mut tracker = PresenceTracker::new(false, 0, DEBOUNCE_MS);
        tracker.begin_waiting();
        tracker.sample(true, 10);
        tracker.sample(true, 39);
        assert!(!tracker.take_confirmation());
        tracker.sample(true, 40);
        assert!(tracker.take_confirmation());
        assert!(!tracker.take_confirmation());
    }

    #[test]
    fn bounce_does_not_confirm() {
        let mut tracker = PresenceTracker::new(false, 0, DEBOUNCE_MS);
        tracker.begin_waiting();
        tracker.sample(true, 10);
        tracker.sample(false, 20);
        tracker.sample(true, 25);
        tracker.sample(false, 40);
        assert!(!tracker.take_confirmation());
    }

    #[test]
    fn press_held_before_request_requires_release_and_new_press() {
        let mut tracker = PresenceTracker::new(true, 0, DEBOUNCE_MS);
        tracker.begin_waiting();
        tracker.sample(true, 100);
        assert!(!tracker.take_confirmation());

        tracker.sample(false, 110);
        tracker.sample(false, 140);
        tracker.sample(true, 150);
        tracker.sample(true, 180);
        assert!(tracker.take_confirmation());
    }

    #[test]
    fn leaving_request_discards_confirmation() {
        let mut tracker = PresenceTracker::new(false, 0, DEBOUNCE_MS);
        tracker.begin_waiting();
        tracker.sample(true, 10);
        tracker.sample(true, 40);
        tracker.end_waiting();
        assert!(!tracker.take_confirmation());
    }

    #[test]
    fn held_press_cannot_confirm_next_request() {
        let mut tracker = PresenceTracker::new(false, 0, DEBOUNCE_MS);
        tracker.begin_waiting();
        tracker.sample(true, 10);
        tracker.sample(true, 40);
        assert!(tracker.take_confirmation());
        tracker.end_waiting();

        tracker.begin_waiting();
        tracker.sample(true, 100);
        assert!(!tracker.take_confirmation());
    }
}
