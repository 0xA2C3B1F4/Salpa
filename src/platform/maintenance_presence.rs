//! Fresh release, five-second hold, then release for irreversible maintenance.

const DEBOUNCE_MS: u64 = 25;
const HOLD_MS: u64 = 5_000;
const TIMEOUT_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    InitialRelease,
    AwaitPress,
    Holding,
    FinalRelease,
    Finished,
}

pub struct MaintenancePresence {
    state: State,
    started: u64,
    changed: u64,
    last_pressed: bool,
}

impl MaintenancePresence {
    pub fn new(pressed: bool, now_ms: u64) -> Self {
        Self {
            state: State::InitialRelease,
            started: now_ms,
            changed: now_ms,
            last_pressed: pressed,
        }
    }

    /// Some(true) is a one-time approval; every later poll returns Some(false).
    /// Cancellation and expiry take precedence over a valid final release.
    pub fn poll(&mut self, pressed: bool, now_ms: u64, cancelled: bool) -> Option<bool> {
        if cancelled
            || now_ms < self.changed
            || now_ms.saturating_sub(self.started) >= TIMEOUT_MS
            || self.state == State::Finished
        {
            self.state = State::Finished;
            return Some(false);
        }
        if pressed != self.last_pressed {
            self.last_pressed = pressed;
            self.changed = now_ms;
        }
        let stable_ms = now_ms.saturating_sub(self.changed);
        match self.state {
            State::InitialRelease if !pressed && stable_ms >= DEBOUNCE_MS => {
                self.state = State::AwaitPress;
            }
            State::AwaitPress if pressed && stable_ms >= DEBOUNCE_MS => {
                self.state = State::Holding;
            }
            State::Holding if !pressed => self.state = State::InitialRelease,
            State::Holding if stable_ms >= HOLD_MS => self.state = State::FinalRelease,
            State::FinalRelease if !pressed && stable_ms >= DEBOUNCE_MS => {
                self.state = State::Finished;
                return Some(true);
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held() -> MaintenancePresence {
        let mut presence = MaintenancePresence::new(false, 0);
        assert_eq!(presence.poll(false, 25, false), None);
        assert_eq!(presence.poll(true, 100, false), None);
        assert_eq!(presence.poll(true, 125, false), None);
        assert_eq!(presence.poll(true, 5100, false), None);
        presence
    }

    #[test]
    fn held_at_start_or_a_short_press_does_not_approve() {
        let mut presence = MaintenancePresence::new(true, 0);
        for time in [25, 100, 5100, 10000] {
            assert_eq!(presence.poll(true, time, false), None);
        }
        for (pressed, time) in [
            (false, 10001),
            (false, 10026),
            (true, 10100),
            (true, 10125),
            (false, 10500),
            (false, 16000),
        ] {
            assert_eq!(presence.poll(pressed, time, false), None);
        }
        assert_eq!(presence.poll(false, 30000, false), Some(false));
    }

    #[test]
    fn long_hold_requires_release_and_is_consumed_exactly_once() {
        let mut presence = held();
        assert_eq!(presence.poll(false, 5101, false), None);
        assert_eq!(presence.poll(false, 5126, false), Some(true));
        assert_eq!(presence.poll(false, 5127, false), Some(false));
    }

    #[test]
    fn cancellation_and_expiry_win_even_at_the_final_release() {
        for (now, cancelled) in [(5126, true), (30000, false)] {
            let mut presence = held();
            assert_eq!(presence.poll(false, 5101, false), None);
            assert_eq!(presence.poll(false, now, cancelled), Some(false));
        }
    }

    #[test]
    fn a_break_in_the_hold_restarts_the_required_duration() {
        let mut presence = MaintenancePresence::new(false, 0);
        for (pressed, time) in [
            (false, 25),
            (true, 100),
            (true, 125),
            (true, 5099),
            (false, 5100),
            (false, 5125),
            (true, 5200),
            (true, 5225),
            (false, 5300),
            (false, 6000),
        ] {
            assert_eq!(presence.poll(pressed, time, false), None);
        }
    }
}
