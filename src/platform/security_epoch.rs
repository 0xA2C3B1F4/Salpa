//! Policy for an explicitly approved ESP32-S2 security-epoch change.
//!
//! This module performs no hardware access. A maintenance transport must bind
//! independently verified slot evidence and fresh physical approval to this
//! policy before a separately reviewed programming backend can use its output.

const FIELD_WORD: usize = 4;
const FIELD_SHIFT: u32 = 11;
const FIELD_MASK: u32 = 0xffff << FIELD_SHIFT;
const SHARED_WRITE_DISABLE: u32 = 1 << 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotEvidence {
    pub signature_verified: bool,
    pub metadata_valid: bool,
    pub secure_version: u32,
    pub signed_content_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedState {
    pub device_digest: [u8; 32],
    pub bootloader_digest: [u8; 32],
    pub trusted_root_digest: [u8; 32],
    pub block0: [u32; 6],
    pub running_slot: u8,
    pub slots: [SlotEvidence; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedPlan {
    pub device_digest: [u8; 32],
    pub bootloader_digest: [u8; 32],
    pub trusted_root_digest: [u8; 32],
    pub expected_block0: [u32; 6],
    /// Digests of the exact images independently qualified for each slot.
    pub qualified_image_digests: [[u8; 32]; 2],
    pub target_epoch: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    Identity,
    Bootloader,
    TrustRoot,
    ChangedEfuses,
    ProtectionDisabled,
    WriteProtected,
    EpochRange,
    NoAdvance,
    RunningSlot,
    UnqualifiedSlot,
    ChangedImage,
    IncompatibleSlot,
    Readback,
}

/// An exact counter-only delta. Constructed only after all policy checks pass.
/// It is deliberately not Copy or Clone; a future backend should consume it
/// for one attempted programming transaction and never retry automatically.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedChange {
    before: [u32; 6],
    after: [u32; 6],
    delta: u16,
    target_epoch: u8,
}

impl PreparedChange {
    pub fn target_epoch(&self) -> u8 {
        self.target_epoch
    }

    pub fn bits_to_program(&self) -> u16 {
        self.delta
    }

    /// These are BLOCK0 program-register values, not an existing block image.
    /// Every bit outside SECURE_VERSION is zero, including shared WR_DIS.
    pub fn program_words(&self) -> [u32; 8] {
        let mut words = [0; 8];
        words[FIELD_WORD] = u32::from(self.delta) << FIELD_SHIFT;
        words
    }

    pub fn recheck_before(&self, block0: &[u32; 6]) -> Result<(), PlanError> {
        if *block0 == self.before {
            Ok(())
        } else {
            Err(PlanError::ChangedEfuses)
        }
    }

    pub fn verify_after(self, block0: &[u32; 6]) -> Result<(), PlanError> {
        if *block0 == self.after {
            Ok(())
        } else {
            Err(PlanError::Readback)
        }
    }
}

pub fn secure_version_raw(block0: &[u32; 6]) -> u16 {
    ((block0[FIELD_WORD] & FIELD_MASK) >> FIELD_SHIFT) as u16
}

pub fn prepare(plan: &ApprovedPlan, observed: &ObservedState) -> Result<PreparedChange, PlanError> {
    if plan.device_digest != observed.device_digest {
        return Err(PlanError::Identity);
    }
    if plan.bootloader_digest != observed.bootloader_digest {
        return Err(PlanError::Bootloader);
    }
    if plan.trusted_root_digest != observed.trusted_root_digest {
        return Err(PlanError::TrustRoot);
    }
    if plan.expected_block0 != observed.block0 {
        return Err(PlanError::ChangedEfuses);
    }
    let secure_boot = observed.block0[3] & (1 << 20) != 0;
    let flash_crypt_count = (observed.block0[2] >> 18) & 7;
    if !secure_boot || flash_crypt_count.count_ones() % 2 != 1 {
        return Err(PlanError::ProtectionDisabled);
    }
    if observed.block0[0] & SHARED_WRITE_DISABLE != 0 {
        return Err(PlanError::WriteProtected);
    }
    if plan.target_epoch > 16 {
        return Err(PlanError::EpochRange);
    }
    let current = secure_version_raw(&observed.block0);
    let count = current.count_ones();
    if u32::from(plan.target_epoch) <= count {
        return Err(PlanError::NoAdvance);
    }
    if observed.running_slot > 1 {
        return Err(PlanError::RunningSlot);
    }
    for (index, slot) in observed.slots.iter().enumerate() {
        if !slot.signature_verified || !slot.metadata_valid {
            return Err(PlanError::UnqualifiedSlot);
        }
        if slot.secure_version < u32::from(plan.target_epoch) || slot.secure_version > 16 {
            return Err(PlanError::IncompatibleSlot);
        }
        if slot.signed_content_digest != plan.qualified_image_digests[index] {
            return Err(PlanError::ChangedImage);
        }
    }

    let mut delta = 0_u16;
    let mut remaining = u32::from(plan.target_epoch) - count;
    for bit in 0..16 {
        let mask = 1_u16 << bit;
        if current & mask == 0 && remaining > 0 {
            delta |= mask;
            remaining -= 1;
        }
    }
    let mut after = observed.block0;
    after[FIELD_WORD] |= u32::from(delta) << FIELD_SHIFT;
    Ok(PreparedChange {
        before: observed.block0,
        after,
        delta,
        target_epoch: plan.target_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(raw: u16, target: u8) -> (ApprovedPlan, ObservedState) {
        let mut block0 = [
            0x100,
            0xa5,
            0x1234 | (7 << 18),
            0x42 | (1 << 20),
            0x8000_0001,
            0x5678,
        ];
        block0[FIELD_WORD] |= u32::from(raw) << FIELD_SHIFT;
        let plan = ApprovedPlan {
            device_digest: [1; 32],
            bootloader_digest: [2; 32],
            trusted_root_digest: [3; 32],
            expected_block0: block0,
            qualified_image_digests: [[4; 32]; 2],
            target_epoch: target,
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
                secure_version: 16,
                signed_content_digest: [4; 32],
            }; 2],
        };
        (plan, observed)
    }

    #[test]
    fn epoch_four_programs_four_bits_and_no_shared_locks() {
        let (plan, observed) = fixture(0, 4);
        let change = prepare(&plan, &observed).unwrap();
        assert_eq!(change.target_epoch(), 4);
        assert_eq!(change.bits_to_program(), 0xf);
        assert_eq!(change.program_words(), [0, 0, 0, 0, 0xf << 11, 0, 0, 0]);
        let mut after = observed.block0;
        after[4] |= 0xf << 11;
        assert_eq!(change.verify_after(&after), Ok(()));
    }

    #[test]
    fn noncontiguous_existing_bits_are_preserved() {
        let (plan, observed) = fixture(0x8005, 5);
        let change = prepare(&plan, &observed).unwrap();
        assert_eq!(change.bits_to_program(), 0xa);
        let mut after = observed.block0;
        after[4] |= 0xa << FIELD_SHIFT;
        assert_eq!(secure_version_raw(&after), 0x800f);
        assert_eq!(secure_version_raw(&after).count_ones(), 5);
        assert_eq!(change.verify_after(&after), Ok(()));
    }

    #[test]
    fn a_different_signed_image_with_the_same_epoch_is_not_qualified() {
        for index in 0..2 {
            let (plan, mut observed) = fixture(0, 4);
            observed.slots[index].signed_content_digest[0] ^= 1;
            assert_eq!(prepare(&plan, &observed), Err(PlanError::ChangedImage));
        }
    }

    #[test]
    fn every_counter_pattern_preserves_set_bits_and_reaches_the_requested_count() {
        for raw in 0..=u16::MAX {
            for target in (raw.count_ones() + 1)..=16 {
                let (plan, observed) = fixture(raw, target as u8);
                let change = prepare(&plan, &observed).unwrap();
                let delta = change.bits_to_program();
                assert_eq!(delta & raw, 0);
                assert_eq!((raw | delta).count_ones(), target);
                let words = change.program_words();
                assert_eq!(words[FIELD_WORD] & !FIELD_MASK, 0);
                for (index, value) in words.into_iter().enumerate() {
                    if index != FIELD_WORD {
                        assert_eq!(value, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn the_last_available_bit_can_be_used_but_exhaustion_cannot_wrap() {
        let (plan, observed) = fixture(0xfffe, 16);
        assert_eq!(prepare(&plan, &observed).unwrap().bits_to_program(), 1);
        for (raw, target, error) in [
            (0xffff, 16, PlanError::NoAdvance),
            (0xffff, 17, PlanError::EpochRange),
            (0xf, 3, PlanError::NoAdvance),
            (0xf, 4, PlanError::NoAdvance),
        ] {
            let (plan, observed) = fixture(raw, target);
            assert_eq!(prepare(&plan, &observed), Err(error));
        }
    }

    #[test]
    fn both_slots_need_valid_metadata_signatures_and_a_compatible_epoch() {
        for slot in 0..2 {
            for defect in 0..4 {
                let (plan, mut observed) = fixture(0, 4);
                match defect {
                    0 => observed.slots[slot].signature_verified = false,
                    1 => observed.slots[slot].metadata_valid = false,
                    2 => observed.slots[slot].secure_version = 3,
                    _ => observed.slots[slot].secure_version = 17,
                }
                assert_eq!(
                    prepare(&plan, &observed),
                    Err(if defect < 2 {
                        PlanError::UnqualifiedSlot
                    } else {
                        PlanError::IncompatibleSlot
                    })
                );
            }
        }
    }

    #[test]
    fn device_bootloader_and_signing_root_are_independently_bound() {
        for (field, expected) in [
            (0, PlanError::Identity),
            (1, PlanError::Bootloader),
            (2, PlanError::TrustRoot),
        ] {
            let (plan, mut observed) = fixture(0, 4);
            match field {
                0 => observed.device_digest[0] ^= 1,
                1 => observed.bootloader_digest[0] ^= 1,
                _ => observed.trusted_root_digest[0] ^= 1,
            }
            assert_eq!(prepare(&plan, &observed), Err(expected));
        }
    }

    #[test]
    fn changed_fuses_or_shared_write_protection_stop_preparation() {
        for word in 0..6 {
            let (plan, mut observed) = fixture(0, 4);
            observed.block0[word] ^= 1;
            assert_eq!(prepare(&plan, &observed), Err(PlanError::ChangedEfuses));
        }
        let (mut plan, mut observed) = fixture(0, 4);
        plan.expected_block0[0] |= SHARED_WRITE_DISABLE;
        observed.block0 = plan.expected_block0;
        assert_eq!(prepare(&plan, &observed), Err(PlanError::WriteProtected));
    }

    #[test]
    fn disabled_protection_or_invalid_running_slot_is_rejected() {
        for defect in 0..3 {
            let (mut plan, mut observed) = fixture(0, 4);
            match defect {
                0 => observed.block0[3] &= !(1 << 20),
                1 => observed.block0[2] &= !(7 << 18),
                _ => observed.running_slot = 2,
            }
            plan.expected_block0 = observed.block0;
            assert_eq!(
                prepare(&plan, &observed),
                Err(if defect < 2 {
                    PlanError::ProtectionDisabled
                } else {
                    PlanError::RunningSlot
                })
            );
        }
    }

    #[test]
    fn stale_preflight_partial_programming_and_unrelated_bit_changes_fail() {
        let (plan, observed) = fixture(0, 4);
        let change = prepare(&plan, &observed).unwrap();
        assert_eq!(change.recheck_before(&observed.block0), Ok(()));
        let mut partial = observed.block0;
        partial[4] |= 3 << FIELD_SHIFT;
        assert_eq!(
            change.recheck_before(&partial),
            Err(PlanError::ChangedEfuses)
        );
        assert_eq!(change.verify_after(&partial), Err(PlanError::Readback));
        for word in 0..6 {
            let change = prepare(&plan, &observed).unwrap();
            let mut after = observed.block0;
            after[4] |= 0xf << FIELD_SHIFT;
            after[word] ^= 1;
            assert_eq!(change.verify_after(&after), Err(PlanError::Readback));
        }
    }
}
