//! A single counter-programming attempt, independent of the hardware adapter.
//!
//! The caller must obtain fresh physical approval and exclusive access to the
//! eFuse peripheral. Constructing a plan or this transaction grants no approval.
//! A backend must implement BLOCK0 only, never a caller-selected key block.

use super::security_epoch::{PlanError, PreparedChange};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub block0: [u32; 6],
    pub repeat_errors: [u32; 5],
}

/// The staging area includes all eight data words and three RS check words.
/// BLOCK0 uses repetition coding; its RS staging words must remain zero.
pub trait Backend {
    fn apb_hz(&self) -> u32;
    fn idle(&self) -> bool;
    fn set_timing(&mut self) -> bool;
    fn refresh(&mut self) -> bool;
    fn snapshot(&self) -> Snapshot;
    fn clear_staging(&mut self);
    fn staging(&self) -> [u32; 11];
    fn stage_counter(&mut self, words: [u32; 8]);
    fn program_block0(&mut self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionError {
    AlreadyAttempted,
    Clock,
    Busy,
    Timing,
    Refresh,
    Coding,
    State(PlanError),
    Staging,
    Program,
}

impl TransactionError {
    /// Stable, non-secret diagnostic for the maintenance failure response.
    pub const fn status_code(self) -> u8 {
        match self {
            Self::AlreadyAttempted => 1,
            Self::Clock => 2,
            Self::Busy => 3,
            Self::Timing => 4,
            Self::Refresh => 5,
            Self::Coding => 6,
            Self::State(_) => 7,
            Self::Staging => 8,
            Self::Program => 9,
        }
    }
}

/// Follow espefuse v5.4.0's ESP32-S2 command-idle check. READ_CMD must be
/// sampled twice due to a hardware clock issue. The STATUS reset value is
/// not an idle-state contract: the observed idle controller reports state 1.
pub fn controller_commands_idle(mut read_command: impl FnMut() -> u32) -> bool {
    read_command() & 3 == 0 && read_command() & 3 == 0
}

/// One attempt per instance, including failed preflight. Never retry a burn
/// automatically after a partial result, timeout or transport interruption.
pub struct Transaction<B> {
    backend: B,
    attempted: bool,
}

impl<B: Backend> Transaction<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            attempted: false,
        }
    }

    pub fn attempt(&mut self, change: PreparedChange) -> Result<(), TransactionError> {
        if self.attempted {
            return Err(TransactionError::AlreadyAttempted);
        }
        self.attempted = true;
        // This maintenance profile qualifies only the fixed 80 MHz APB setup.
        if self.backend.apb_hz() != 80_000_000 {
            return Err(TransactionError::Clock);
        }
        if !self.backend.idle() {
            return Err(TransactionError::Busy);
        }
        if !self.backend.set_timing() {
            return Err(TransactionError::Timing);
        }
        if !self.backend.refresh() {
            return Err(TransactionError::Refresh);
        }
        check_before(&change, self.backend.snapshot())?;

        self.backend.clear_staging();
        if self.backend.staging() != [0; 11] {
            return Err(TransactionError::Staging);
        }
        let words = change.program_words();
        let mut expected = [0; 11];
        expected[..8].copy_from_slice(&words);
        self.backend.stage_counter(words);
        let staged = if self.backend.staging() != expected {
            Err(TransactionError::Staging)
        } else if !self.backend.idle() {
            Err(TransactionError::Busy)
        } else {
            check_before(&change, self.backend.snapshot())
        };
        if let Err(error) = staged {
            self.backend.clear_staging();
            return Err(error);
        }

        // Exactly one physical call. Even an error result may have burned bits.
        let programmed = self.backend.program_block0();
        self.backend.clear_staging();
        let cleared = self.backend.staging() == [0; 11];
        let refreshed = self.backend.refresh();
        let after = self.backend.snapshot();
        if !cleared {
            return Err(TransactionError::Staging);
        }
        if !refreshed {
            return Err(TransactionError::Refresh);
        }
        if after.repeat_errors != [0; 5] {
            return Err(TransactionError::Coding);
        }
        change
            .verify_after(&after.block0)
            .map_err(TransactionError::State)?;
        if !programmed {
            return Err(TransactionError::Program);
        }
        Ok(())
    }
}

fn check_before(change: &PreparedChange, snapshot: Snapshot) -> Result<(), TransactionError> {
    if snapshot.repeat_errors != [0; 5] {
        return Err(TransactionError::Coding);
    }
    change
        .recheck_before(&snapshot.block0)
        .map_err(TransactionError::State)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::security_epoch::{ApprovedPlan, ObservedState, SlotEvidence, prepare};

    #[test]
    fn idle_requires_two_clear_command_samples() {
        for (samples, expected) in [
            ([0, 0], true),
            ([0, 1], false),
            ([0, 2], false),
            ([1, 0], false),
            ([2, 0], false),
        ] {
            let mut values = samples.into_iter();
            assert_eq!(
                controller_commands_idle(|| values.next().unwrap()),
                expected
            );
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        None,
        Clock,
        Busy,
        Timing,
        RefreshBefore,
        StaleBefore,
        CodingBefore,
        ClearBefore,
        WrongData,
        StaleAfterStaging,
        CodingAfterStaging,
        BusyAfterStaging,
        PartialBurn,
        UnrelatedBurn,
        ReportedBurnFailure,
        ClearAfter,
        RefreshAfter,
        CodingAfter,
    }

    struct Fake {
        fault: Fault,
        state: Snapshot,
        staged: [u32; 11],
        staged_once: bool,
        burns: usize,
        clears: usize,
        refreshes: usize,
    }

    fn fixture(fault: Fault) -> (Fake, PreparedChange) {
        let block0 = [0x100, 1, 7 << 18, 1 << 20, 0, 0];
        let plan = ApprovedPlan {
            device_digest: [1; 32],
            bootloader_digest: [2; 32],
            trusted_root_digest: [3; 32],
            expected_block0: block0,
            qualified_image_digests: [[4; 32]; 2],
            target_epoch: 4,
        };
        let observed = ObservedState {
            device_digest: plan.device_digest,
            bootloader_digest: plan.bootloader_digest,
            trusted_root_digest: plan.trusted_root_digest,
            block0,
            running_slot: 0,
            slots: [SlotEvidence {
                signature_verified: true,
                metadata_valid: true,
                secure_version: 4,
                signed_content_digest: [4; 32],
            }; 2],
        };
        let fake = Fake {
            fault,
            state: Snapshot {
                block0,
                repeat_errors: [0; 5],
            },
            staged: [0xa5; 11],
            staged_once: false,
            burns: 0,
            clears: 0,
            refreshes: 0,
        };
        (fake, prepare(&plan, &observed).unwrap())
    }

    impl Backend for Fake {
        fn apb_hz(&self) -> u32 {
            if self.fault == Fault::Clock {
                40_000_000
            } else {
                80_000_000
            }
        }

        fn idle(&self) -> bool {
            self.fault != Fault::Busy
                && !(self.fault == Fault::BusyAfterStaging && self.staged_once)
        }

        fn set_timing(&mut self) -> bool {
            self.fault != Fault::Timing
        }

        fn refresh(&mut self) -> bool {
            self.refreshes += 1;
            !matches!(
                (self.fault, self.refreshes),
                (Fault::RefreshBefore, 1) | (Fault::RefreshAfter, 2)
            )
        }

        fn snapshot(&self) -> Snapshot {
            let mut state = self.state;
            if self.fault == Fault::StaleBefore
                || (self.fault == Fault::StaleAfterStaging && self.staged_once)
            {
                state.block0[0] ^= 1;
            }
            if self.fault == Fault::CodingBefore
                || (self.fault == Fault::CodingAfterStaging && self.staged_once)
                || (self.fault == Fault::CodingAfter && self.burns > 0)
            {
                state.repeat_errors[3] = 1 << 11;
            }
            state
        }

        fn clear_staging(&mut self) {
            self.clears += 1;
            self.staged = [0; 11];
            if matches!(
                (self.fault, self.clears),
                (Fault::ClearBefore, 1) | (Fault::ClearAfter, 2)
            ) {
                self.staged[10] = 1;
            }
        }

        fn staging(&self) -> [u32; 11] {
            self.staged
        }

        fn stage_counter(&mut self, words: [u32; 8]) {
            self.staged[..8].copy_from_slice(&words);
            self.staged_once = true;
            if self.fault == Fault::WrongData {
                self.staged[0] = 1 << 18;
            }
        }

        fn program_block0(&mut self) -> bool {
            self.burns += 1;
            assert_eq!(self.burns, 1);
            assert_eq!(self.staged, [0, 0, 0, 0, 15 << 11, 0, 0, 0, 0, 0, 0]);
            self.state.block0[4] |= if self.fault == Fault::PartialBurn {
                3 << 11
            } else {
                15 << 11
            };
            if self.fault == Fault::UnrelatedBurn {
                self.state.block0[0] |= 1 << 18;
            }
            self.fault != Fault::ReportedBurnFailure
        }
    }

    #[test]
    fn a_successful_attempt_clears_staging_and_refreshes_actual_readback() {
        let (backend, change) = fixture(Fault::None);
        let mut transaction = Transaction::new(backend);
        assert_eq!(transaction.attempt(change), Ok(()));
        assert_eq!(transaction.backend.burns, 1);
        assert_eq!(transaction.backend.clears, 2);
        assert_eq!(transaction.backend.refreshes, 2);
        assert_eq!(transaction.backend.staged, [0; 11]);
        assert_eq!(
            transaction.attempt(fixture(Fault::None).1),
            Err(TransactionError::AlreadyAttempted)
        );
    }

    #[test]
    fn every_preflight_failure_prevents_programming_and_latches_the_attempt() {
        for fault in [
            Fault::Clock,
            Fault::Busy,
            Fault::Timing,
            Fault::RefreshBefore,
            Fault::StaleBefore,
            Fault::CodingBefore,
            Fault::ClearBefore,
            Fault::WrongData,
            Fault::StaleAfterStaging,
            Fault::CodingAfterStaging,
            Fault::BusyAfterStaging,
        ] {
            let (backend, change) = fixture(fault);
            let mut transaction = Transaction::new(backend);
            assert!(transaction.attempt(change).is_err(), "{fault:?}");
            assert_eq!(transaction.backend.burns, 0, "{fault:?}");
            if transaction.backend.staged_once {
                assert_eq!(transaction.backend.staged, [0; 11], "{fault:?}");
            }
            assert_eq!(
                transaction.attempt(fixture(Fault::None).1),
                Err(TransactionError::AlreadyAttempted),
                "{fault:?}"
            );
        }
    }

    #[test]
    fn uncertain_results_are_never_reported_as_success_or_retried() {
        for (fault, expected) in [
            (
                Fault::PartialBurn,
                TransactionError::State(PlanError::Readback),
            ),
            (
                Fault::UnrelatedBurn,
                TransactionError::State(PlanError::Readback),
            ),
            (Fault::ReportedBurnFailure, TransactionError::Program),
            (Fault::ClearAfter, TransactionError::Staging),
            (Fault::RefreshAfter, TransactionError::Refresh),
            (Fault::CodingAfter, TransactionError::Coding),
        ] {
            let (backend, change) = fixture(fault);
            let mut transaction = Transaction::new(backend);
            assert_eq!(transaction.attempt(change), Err(expected), "{fault:?}");
            assert_eq!(transaction.backend.burns, 1, "{fault:?}");
            assert_eq!(transaction.backend.clears, 2, "{fault:?}");
            assert_eq!(transaction.backend.refreshes, 2, "{fault:?}");
            assert_eq!(
                transaction.attempt(fixture(Fault::None).1),
                Err(TransactionError::AlreadyAttempted),
                "{fault:?}"
            );
            assert_eq!(transaction.backend.burns, 1, "{fault:?}");
        }
    }
}
