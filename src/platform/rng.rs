//! ESP hardware true-random source for Trussed.

use esp_hal::rng::{Trng, TrngError, TrngSource};
use rand_core::{CryptoRng, Error, RngCore};
use zeroize::Zeroize as _;

use super::rng_health::{StartupSanityError, check_blocks};

const SANITY_BLOCK_SIZE: usize = 32;

/// Owns the HAL entropy source for as long as Trussed can request random data.
///
/// `TrngSource` enables the ESP32-S2/S3 SAR ADC entropy source. Keeping it in
/// this value prevents the source from being dropped while the `Trng` is live.
pub struct HardwareRng {
    rng: Trng,
    _source: TrngSource<'static>,
}

impl HardwareRng {
    pub fn new(source: TrngSource<'static>) -> Result<Self, TrngError> {
        let rng = Trng::try_new()?;
        Ok(Self {
            rng,
            _source: source,
        })
    }

    /// Rejects two obvious hardware failure patterns during development.
    ///
    /// This consumes 64 bytes and must not be described as RNG certification.
    pub fn startup_sanity_check(&mut self) -> Result<(), StartupSanityError> {
        let mut first = [0_u8; SANITY_BLOCK_SIZE];
        let mut second = [0_u8; SANITY_BLOCK_SIZE];
        self.rng.read(&mut first);
        self.rng.read(&mut second);
        let result = check_blocks(&first, &second);
        first.zeroize();
        second.zeroize();
        result
    }
}

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.random()
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.rng.read(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.read(dest);
        Ok(())
    }
}

impl CryptoRng for HardwareRng {}
