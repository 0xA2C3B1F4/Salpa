//! Fresh button consent for authentication and maintenance.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    Released,
    Pressed,
    Uncertain,
    Fault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    InitialRelease,
    AwaitPress,
    FinalRelease,
    Finished,
}

pub struct PresenceGate {
    phase: Phase,
    deadline: u64,
    last_poll: u64,
    last_level: Level,
    since: u64,
    release_ms: u64,
    press_ms: u64,
    long_hold: bool,
}

impl PresenceGate {
    pub const fn ready_for_action(&self) -> bool {
        matches!(self.phase, Phase::AwaitPress)
    }

    pub fn new(now: u64, timeout_ms: u64, long_hold: bool) -> Self {
        Self {
            phase: Phase::InitialRelease,
            deadline: now.saturating_add(timeout_ms),
            last_poll: now,
            last_level: Level::Uncertain,
            since: now,
            release_ms: 30,
            press_ms: if long_hold { 5_000 } else { 30 },
            long_hold,
        }
    }

    /// A missing sample may wait, but cannot advance a gesture. The input
    /// adapter must report Fault when conversions become stale. Cancellation
    /// and timeout win even when the same poll contains a valid final sample.
    pub fn poll(&mut self, sample: Option<Level>, now: u64, cancelled: bool) -> Option<bool> {
        if cancelled
            || now < self.last_poll
            || now >= self.deadline
            || self.phase == Phase::Finished
        {
            self.phase = Phase::Finished;
            return Some(false);
        }
        self.last_poll = now;
        let level = sample?;
        if level == Level::Fault {
            self.phase = Phase::Finished;
            return Some(false);
        }
        if level != self.last_level {
            self.last_level = level;
            self.since = now;
        }
        if level == Level::Uncertain {
            // Noise must never count as part of the hold or final release.
            if self.phase == Phase::FinalRelease {
                self.phase = Phase::InitialRelease;
            }
            return None;
        }
        let stable = now - self.since;
        match self.phase {
            Phase::InitialRelease if level == Level::Released && stable >= self.release_ms => {
                self.phase = Phase::AwaitPress;
            }
            Phase::AwaitPress if level == Level::Pressed && stable >= self.press_ms => {
                if self.long_hold {
                    self.phase = Phase::FinalRelease;
                } else {
                    self.phase = Phase::Finished;
                    return Some(true);
                }
            }
            Phase::FinalRelease if level == Level::Released && stable >= self.release_ms => {
                self.phase = Phase::Finished;
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

    fn armed(long: bool) -> PresenceGate {
        let mut gate = PresenceGate::new(0, 30_000, long);
        assert_eq!(gate.poll(Some(Level::Released), 0, false), None);
        assert_eq!(gate.poll(Some(Level::Released), 150, false), None);
        assert!(gate.ready_for_action());
        gate
    }

    #[test]
    fn button_requires_a_fresh_release_then_press_and_is_one_shot() {
        let mut gate = PresenceGate::new(0, 30_000, false);
        for now in [0, 150, 1000, 5000] {
            assert_eq!(gate.poll(Some(Level::Pressed), now, false), None);
        }
        assert_eq!(gate.poll(Some(Level::Released), 5100, false), None);
        assert_eq!(gate.poll(Some(Level::Released), 5250, false), None);
        assert_eq!(gate.poll(Some(Level::Pressed), 5300, false), None);
        assert_eq!(gate.poll(Some(Level::Pressed), 5380, false), Some(true));
        assert_eq!(gate.poll(Some(Level::Pressed), 5400, false), Some(false));
    }

    #[test]
    fn long_hold_requires_continuity_and_final_release() {
        let mut gate = armed(true);
        assert_eq!(gate.poll(Some(Level::Pressed), 200, false), None);
        assert_eq!(gate.poll(Some(Level::Pressed), 5199, false), None);
        assert_eq!(gate.poll(Some(Level::Uncertain), 5200, false), None);
        assert_eq!(gate.poll(Some(Level::Pressed), 5300, false), None);
        assert_eq!(gate.poll(Some(Level::Pressed), 10300, false), None);
        assert_eq!(gate.poll(Some(Level::Pressed), 11000, false), None);
        assert_eq!(gate.poll(Some(Level::Released), 11001, false), None);
        assert_eq!(gate.poll(Some(Level::Released), 11151, false), Some(true));
    }

    #[test]
    fn cancellation_deadline_fault_and_clock_reversal_win() {
        for failure in 0..4 {
            let mut gate = armed(false);
            gate.poll(Some(Level::Pressed), 200, false);
            let (sample, now, cancel) = match failure {
                0 => (Some(Level::Pressed), 280, true),
                1 => (Some(Level::Pressed), 30_000, false),
                2 => (Some(Level::Fault), 280, false),
                _ => (Some(Level::Pressed), 199, false),
            };
            assert_eq!(gate.poll(sample, now, cancel), Some(false));
            assert_eq!(gate.poll(Some(Level::Pressed), 300, false), Some(false));
        }
    }

    #[test]
    fn noise_and_missing_conversions_do_not_approve() {
        let mut gate = armed(false);
        for now in (200..1000).step_by(10) {
            let level = if now % 20 == 0 {
                Level::Pressed
            } else {
                Level::Uncertain
            };
            assert_eq!(gate.poll(Some(level), now, false), None);
        }
        assert_eq!(gate.poll(None, 2000, false), None);
        assert_eq!(gate.poll(None, 30_000, false), Some(false));
    }
}
