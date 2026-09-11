//! Compile-time description of the FIDO flash partition.

pub const FLASH_SIZE: usize = 4 * 1024 * 1024;
pub const FIDO_STORE_SIZE: usize = 128 * 1024;
pub const FIDO_STORE_OFFSET: usize = FLASH_SIZE - FIDO_STORE_SIZE;

pub const ERASE_SIZE: usize = 4096;
pub const FIDO_STORE_BLOCK_COUNT: usize = FIDO_STORE_SIZE / ERASE_SIZE;

const _: () = {
    assert!(FIDO_STORE_OFFSET == 0x3e0000);
    assert!(FIDO_STORE_SIZE == 0x20000);
    assert!(FIDO_STORE_OFFSET.is_multiple_of(ERASE_SIZE));
    assert!(FIDO_STORE_SIZE.is_multiple_of(ERASE_SIZE));
};

pub fn checked_absolute_range(offset: usize, len: usize) -> Option<(u32, u32)> {
    let end = offset.checked_add(len)?;
    if end > FIDO_STORE_SIZE {
        return None;
    }

    let absolute_start = FIDO_STORE_OFFSET.checked_add(offset)?;
    let absolute_end = FIDO_STORE_OFFSET.checked_add(end)?;
    Some((
        u32::try_from(absolute_start).ok()?,
        u32::try_from(absolute_end).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{FIDO_STORE_OFFSET, FIDO_STORE_SIZE, checked_absolute_range};

    #[test]
    fn maps_partition_relative_offsets() {
        assert_eq!(
            checked_absolute_range(0x1000, 0x2000),
            Some((
                (FIDO_STORE_OFFSET + 0x1000) as u32,
                (FIDO_STORE_OFFSET + 0x3000) as u32
            ))
        );
    }

    #[test]
    fn accepts_exact_partition_end() {
        assert_eq!(
            checked_absolute_range(FIDO_STORE_SIZE, 0),
            Some((
                (FIDO_STORE_OFFSET + FIDO_STORE_SIZE) as u32,
                (FIDO_STORE_OFFSET + FIDO_STORE_SIZE) as u32
            ))
        );
    }

    #[test]
    fn rejects_out_of_partition_range_and_overflow() {
        assert_eq!(checked_absolute_range(FIDO_STORE_SIZE, 1), None);
        assert_eq!(checked_absolute_range(usize::MAX, 2), None);
    }
}
