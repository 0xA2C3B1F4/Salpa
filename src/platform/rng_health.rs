//! Minimal startup sanity checks for hardware RNG output.
//!
//! These checks can catch an obviously stuck source. They are not a statistical
//! test suite and do not certify the RNG.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupSanityError {
    AllZero,
    RepeatedBlock,
}

pub fn check_blocks(first: &[u8], second: &[u8]) -> Result<(), StartupSanityError> {
    if first.iter().chain(second).all(|byte| *byte == 0) {
        return Err(StartupSanityError::AllZero);
    }
    if first == second {
        return Err(StartupSanityError::RepeatedBlock);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{StartupSanityError, check_blocks};

    #[test]
    fn accepts_distinct_nonzero_blocks() {
        assert_eq!(check_blocks(&[1, 2, 3], &[1, 2, 4]), Ok(()));
    }

    #[test]
    fn rejects_all_zero_output() {
        assert_eq!(
            check_blocks(&[0; 8], &[0; 8]),
            Err(StartupSanityError::AllZero)
        );
    }

    #[test]
    fn rejects_repeated_output() {
        assert_eq!(
            check_blocks(&[7; 8], &[7; 8]),
            Err(StartupSanityError::RepeatedBlock)
        );
    }
}
