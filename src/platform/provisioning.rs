//! Physical confirmation state for destructive storage provisioning.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningGesture {
    required_hold_ms: u64,
    release_seen: bool,
    pressed_since_ms: Option<u64>,
}

impl ProvisioningGesture {
    pub const fn new(required_hold_ms: u64) -> Self {
        Self {
            required_hold_ms,
            release_seen: false,
            pressed_since_ms: None,
        }
    }

    /// Returns true only after a post-boot release and a continuous hold.
    pub fn sample(&mut self, pressed: bool, now_ms: u64) -> bool {
        if !pressed {
            self.release_seen = true;
            self.pressed_since_ms = None;
            return false;
        }

        if !self.release_seen {
            return false;
        }

        let pressed_since_ms = *self.pressed_since_ms.get_or_insert(now_ms);
        now_ms.saturating_sub(pressed_since_ms) >= self.required_hold_ms
    }
}

#[cfg(test)]
mod tests {
    use super::ProvisioningGesture;

    const HOLD_MS: u64 = 5_000;

    #[test]
    fn button_held_at_boot_never_confirms() {
        let mut gesture = ProvisioningGesture::new(HOLD_MS);
        assert!(!gesture.sample(true, 0));
        assert!(!gesture.sample(true, 10_000));
    }

    #[test]
    fn fresh_continuous_hold_confirms_at_threshold() {
        let mut gesture = ProvisioningGesture::new(HOLD_MS);
        assert!(!gesture.sample(false, 10));
        assert!(!gesture.sample(true, 20));
        assert!(!gesture.sample(true, 5_019));
        assert!(gesture.sample(true, 5_020));
    }

    #[test]
    fn release_during_hold_restarts_timer() {
        let mut gesture = ProvisioningGesture::new(HOLD_MS);
        assert!(!gesture.sample(false, 0));
        assert!(!gesture.sample(true, 100));
        assert!(!gesture.sample(false, 4_000));
        assert!(!gesture.sample(true, 4_100));
        assert!(!gesture.sample(true, 8_999));
        assert!(gesture.sample(true, 9_100));
    }
}
