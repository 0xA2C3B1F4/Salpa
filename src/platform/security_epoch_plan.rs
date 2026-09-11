//! Private, fixed scope embedded in a separately signed maintenance image.
//!
//! The non-running slot is bound to an independently qualified normal image.
//! The running maintenance image must pass boot, credential, signature and
//! VALID-metadata checks before its counter operation can be approved.

pub const PLAN_BYTES: usize = 164;

/// Exact request binding. The target epoch is never accepted from a request.
pub fn requested_images(request: &[u8], plan_digest: &[u8; 32]) -> Option<Option<[[u8; 32]; 2]>> {
    if request == [0x13] {
        return Some(None);
    }
    if request.len() != 97 || !matches!(request[0], 0x14 | 0x15) || request[1..33] != *plan_digest {
        return None;
    }
    Some(Some([
        request[33..65].try_into().ok()?,
        request[65..97].try_into().ok()?,
    ]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenancePlan {
    pub device_digest: [u8; 32],
    pub bootloader_digest: [u8; 32],
    pub trusted_root_digest: [u8; 32],
    pub expected_block0: [u32; 6],
    pub fallback_digest: [u8; 32],
    pub target_epoch: u8,
    pub revision_major: u8,
    pub revision_minor: u8,
}

pub fn decode(bytes: &[u8]) -> Option<MaintenancePlan> {
    if bytes.len() != PLAN_BYTES || &bytes[..8] != b"RKMPLAN1" || bytes[163] != 0 {
        return None;
    }
    let mut block0 = [0; 6];
    for (word, bytes) in block0.iter_mut().zip(bytes[104..128].chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().ok()?);
    }
    let plan = MaintenancePlan {
        device_digest: bytes[8..40].try_into().ok()?,
        bootloader_digest: bytes[40..72].try_into().ok()?,
        trusted_root_digest: bytes[72..104].try_into().ok()?,
        expected_block0: block0,
        fallback_digest: bytes[128..160].try_into().ok()?,
        target_epoch: bytes[160],
        revision_major: bytes[161],
        revision_minor: bytes[162],
    };
    if !(1..=16).contains(&plan.target_epoch)
        || block0[0] & (1 << 18) != 0
        || u32::from(plan.target_epoch)
            <= super::security_epoch::secure_version_raw(&block0).count_ones()
        || [
            plan.device_digest,
            plan.bootloader_digest,
            plan.trusted_root_digest,
            plan.fallback_digest,
        ]
        .contains(&[0; 32])
    {
        return None;
    }
    Some(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_plan_bound_requests_can_rehearse_or_program() {
        let mut request = [7; 97];
        assert_eq!(requested_images(&[0x13], &[7; 32]), Some(None));
        for command in [0x14, 0x15] {
            request[0] = command;
            assert_eq!(
                requested_images(&request, &[7; 32]),
                Some(Some([[7; 32]; 2]))
            );
        }
        for length in 0..97 {
            assert_eq!(requested_images(&request[..length], &[7; 32]), None);
        }
        for command in [0, 0x12, 0x13, 0x16, 0xff] {
            request[0] = command;
            assert_eq!(requested_images(&request, &[7; 32]), None);
        }
        request[0] = 0x14;
        assert_eq!(requested_images(&request, &[8; 32]), None);
    }

    #[test]
    fn malformed_scope_and_exhausted_or_locked_counters_are_rejected() {
        let mut bytes = [1; PLAN_BYTES];
        bytes[..8].copy_from_slice(b"RKMPLAN1");
        bytes[104..128].fill(0);
        bytes[160..].copy_from_slice(&[4, 1, 0, 0]);
        assert_eq!(decode(&bytes).unwrap().target_epoch, 4);
        for (index, value) in [(0, 0), (160, 0), (160, 17), (163, 1), (106, 4)] {
            let mut invalid = bytes;
            invalid[index] = value;
            assert!(decode(&invalid).is_none());
        }
        let mut exhausted = bytes;
        exhausted[120..124].copy_from_slice(&(0xffff_u32 << 11).to_le_bytes());
        assert!(decode(&exhausted).is_none());
        for range in [8..40, 40..72, 72..104, 128..160] {
            let mut invalid = bytes;
            invalid[range].fill(0);
            assert!(decode(&invalid).is_none());
        }
        for length in 0..PLAN_BYTES {
            assert!(decode(&bytes[..length]).is_none());
        }
    }
}
