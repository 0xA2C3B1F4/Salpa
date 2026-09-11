//! ESP32-S2 SRAM permissions. No flash or eFuse writes.
//!
//! Register encoding follows Espressif's Apache-2.0 memprot implementation at
//! fff9895c82d744c7237be8847347bdd1b07c6643; see the memory-protection guide.
//! Code is RX, its DRAM alias is read-only, and data cannot execute through
//! its IRAM alias. RTC fast/slow memory is non-executable. Locks reset on CPU
//! restart; an incompatible inherited locked policy fails closed.

pub const REQUEST: u8 = 0x14;
pub const RESPONSE_SIZE: usize = 64;
const SRAM_ALIAS_OFFSET: u32 = 0x70000;
const MIN_IRAM_SPLIT: u32 = 0x4002_8000;
const MAX_IRAM_SPLIT: u32 = 0x4005_0000;

// Offsets in ESP32-S2 PMS, base 0x3f4c1000. The four buses are IRAM, DRAM,
// peripheral DPORT and AHB. Only the listed permission bits are modified.
const LOCKS: [usize; 4] = [0x10, 0x28, 0x3c, 0x5c];
const MONITORS: [usize; 4] = [0x20, 0x34, 0x54, 0x68];
const PERMISSIONS: [(usize, u32); 8] = [
    (0x14, 0xfff),
    (0x18, 0x7fffff),
    (0x1c, 0x1ffff),
    (0x2c, 0x1fffffff),
    (0x30, 0x7fff),
    (0x40, 0xfffe),
    (0x60, 0x1ffff),
    (0x64, 0x1ffff),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Layout,
    LockedPolicy,
    Readback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Policy {
    iram_end: u32,
    data_start: u32,
    values: [u32; 8],
}

impl Policy {
    fn new(iram_end: u32, data_start: u32) -> Result<Self, Error> {
        if !(MIN_IRAM_SPLIT..MAX_IRAM_SPLIT).contains(&iram_end)
            || !iram_end.is_multiple_of(4)
            || iram_end.checked_sub(SRAM_ALIAS_OFFSET) != Some(data_start)
        {
            return Err(Error::Layout);
        }
        Ok(Self {
            iram_end,
            data_start,
            values: [
                // Coarse SRAM blocks 0..3: read + fetch, never write.
                0x6db,
                // Fine SRAM: low RX; high denies all IRAM-bus access.
                ((iram_end >> 2) & 0x1ffff) | (1 << 18) | (1 << 17),
                // No execution or data access through the RTC instruction alias.
                0,
                // DRAM: coarse blocks read-only; low read-only; high read/write.
                0x55 | (((data_start >> 2) & 0x1ffff) << 8) | (1 << 25) | (1 << 27) | (1 << 28),
                // RTC fast data alias: read/write on both sides of split zero.
                0x7800,
                // Peripheral alias of RTC slow: deny access, preserve FIFO bits.
                0,
                // RTC slow primary alias: read/write, never fetch.
                (1 << 16) | (1 << 15) | (1 << 13) | (1 << 12),
                // RTC slow secondary alias: deny all access.
                0,
            ],
        })
    }
}

trait Registers {
    fn read(&self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
}

fn replace_bits(registers: &mut impl Registers, offset: usize, mask: u32, value: u32) {
    let previous = registers.read(offset);
    registers.write(offset, (previous & !mask) | (value & mask));
}

fn matches_policy(registers: &impl Registers, policy: &Policy) -> bool {
    PERMISSIONS
        .iter()
        .zip(policy.values)
        .all(|(&(offset, mask), expected)| registers.read(offset) & mask == expected)
        && MONITORS
            .iter()
            .all(|&offset| registers.read(offset) & 7 == 2)
}

fn configure(registers: &mut impl Registers, policy: &Policy) -> Result<(), Error> {
    if LOCKS.iter().any(|&offset| registers.read(offset) & 1 != 0) {
        return if LOCKS.iter().all(|&offset| registers.read(offset) & 1 != 0)
            && matches_policy(registers, policy)
        {
            Ok(())
        } else {
            Err(Error::LockedPolicy)
        };
    }
    // Clear latched faults and disable monitors while installing permissions.
    for offset in MONITORS {
        replace_bits(registers, offset, 3, 1);
        replace_bits(registers, offset, 3, 0);
    }
    for ((offset, mask), value) in PERMISSIONS.into_iter().zip(policy.values) {
        replace_bits(registers, offset, mask, value);
    }
    for offset in MONITORS {
        replace_bits(registers, offset, 3, 2);
    }
    if !matches_policy(registers, policy) {
        return Err(Error::Readback);
    }
    // Lock only after every permission and monitor has been read back.
    for offset in LOCKS {
        registers.write(offset, 1);
    }
    if !LOCKS.iter().all(|&offset| registers.read(offset) & 1 == 1)
        || !matches_policy(registers, policy)
    {
        return Err(Error::Readback);
    }
    Ok(())
}

fn encode_status(registers: &impl Registers, policy: &Policy, output: &mut [u8]) -> usize {
    assert!(output.len() >= RESPONSE_SIZE);
    output.fill(0);
    output[..4].copy_from_slice(b"RKMP");
    output[4] = 1;
    for i in 0..4 {
        output[5] |= ((registers.read(LOCKS[i]) & 1) as u8) << i;
        output[6] |= (((registers.read(MONITORS[i]) >> 1) & 1) as u8) << i;
        output[7] |= (((registers.read(MONITORS[i]) >> 2) & 1) as u8) << i;
    }
    output[8..12].copy_from_slice(&policy.iram_end.to_le_bytes());
    output[12..16].copy_from_slice(&policy.data_start.to_le_bytes());
    for (i, (offset, mask)) in PERMISSIONS.into_iter().enumerate() {
        output[16 + i * 4..20 + i * 4]
            .copy_from_slice(&(registers.read(offset) & mask).to_le_bytes());
    }
    // No raw fault addresses or memory contents cross this interface.
    RESPONSE_SIZE
}

#[cfg(all(feature = "mcu-esp32s2", not(test)))]
mod hardware {
    use super::*;
    use esp_hal::{interrupt, peripherals::Interrupt};

    struct Pms;

    impl Registers for Pms {
        fn read(&self, offset: usize) -> u32 {
            // All callers use the fixed register allowlist above.
            unsafe { core::ptr::read_volatile((0x3f4c_1000 + offset) as *const u32) }
        }

        fn write(&mut self, offset: usize, value: u32) {
            unsafe {
                core::ptr::write_volatile((0x3f4c_1000 + offset) as *mut u32, value);
            }
            // Xtensa lowers this fence to MEMW; verify in the linked image.
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

    fn linked_policy() -> Result<Policy, Error> {
        unsafe extern "C" {
            static _salpa_pms_iram_end: u8;
            static _data_start: u8;
        }
        Policy::new(
            core::ptr::addr_of!(_salpa_pms_iram_end) as u32,
            core::ptr::addr_of!(_data_start) as u32,
        )
    }

    // Never log fault addresses, continue the faulting request, or write flash.
    // RAM placement permits the handler to stop even during cache-disabled I/O.
    #[esp_hal::ram]
    #[esp_hal::handler(priority = esp_hal::interrupt::Priority::Priority3)]
    fn memory_fault() {
        esp_hal::xtensa_lx::interrupt::disable();
        loop {
            core::hint::spin_loop();
        }
    }

    pub fn initialize() -> Result<(), Error> {
        let policy = linked_policy()?;
        critical_section::with(|_| {
            for source in [
                Interrupt::PMS_PRO_IRAM0_ILG,
                Interrupt::PMS_PRO_DRAM0_ILG,
                Interrupt::PMS_PRO_DPORT_ILG,
                Interrupt::PMS_PRO_AHB_ILG,
            ] {
                interrupt::bind_handler(source, memory_fault);
            }
            configure(&mut Pms, &policy)
        })
    }

    pub fn status(output: &mut [u8]) -> usize {
        let policy = linked_policy().expect("validated PMS layout changed");
        encode_status(&Pms, &policy, output)
    }
}

#[cfg(all(feature = "mcu-esp32s2", not(test)))]
pub use hardware::{initialize, status};

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct FakeRegisters {
        words: [u32; 28],
        writes: Vec<(usize, u32)>,
        ignore_write: Option<usize>,
    }

    impl Default for FakeRegisters {
        fn default() -> Self {
            Self {
                words: [0; 28],
                writes: Vec::new(),
                ignore_write: None,
            }
        }
    }

    impl Registers for FakeRegisters {
        fn read(&self, offset: usize) -> u32 {
            self.words[offset / 4]
        }

        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
            if self.ignore_write == Some(offset) {
                return;
            }
            if MONITORS.contains(&offset) {
                let pending = if value & 1 != 0 {
                    0
                } else {
                    self.read(offset) & 4
                };
                self.words[offset / 4] = (value & !4) | pending;
            } else {
                self.words[offset / 4] = value;
            }
        }
    }

    fn policy() -> Policy {
        Policy::new(0x4002_8000, 0x3ffb_8000).unwrap()
    }

    #[test]
    fn rejects_unrepresentable_or_mismatched_layout() {
        for split in [0, 0x4002_7ffc, 0x4002_8001, 0x4005_0000, u32::MAX] {
            assert_eq!(
                Policy::new(split, split.wrapping_sub(SRAM_ALIAS_OFFSET)),
                Err(Error::Layout)
            );
        }
        assert_eq!(Policy::new(0x4002_8000, 0x3ffb_8004), Err(Error::Layout));
        for split in [0x4002_8000, 0x4002_9004, 0x4004_fffc] {
            let p = Policy::new(split, split - SRAM_ALIAS_OFFSET).unwrap();
            assert_eq!((p.values[1] & 0x1ffff) << 2 | 0x4000_0000, split);
            assert_eq!(
                ((p.values[3] >> 8) & 0x1ffff) << 2 | 0x3ff8_0000,
                split - SRAM_ALIAS_OFFSET
            );
        }
    }

    #[test]
    fn code_is_readable_executable_and_never_writable_through_either_alias() {
        let p = policy();
        // Decode the documented W/R/F and W/R fields independently of the setter.
        for block in 0..4 {
            assert_eq!((p.values[0] >> (block * 3)) & 7, 0b011);
            assert_eq!((p.values[3] >> (block * 2)) & 3, 0b01);
        }
        assert_eq!((p.values[1] >> 17) & 7, 0b011);
        assert_eq!((p.values[3] >> 25) & 3, 0b01);
    }

    #[test]
    fn writable_data_and_rtc_have_no_executable_alias() {
        let p = policy();
        assert_eq!((p.values[1] >> 20) & 7, 0);
        assert_eq!((p.values[3] >> 27) & 3, 0b11);
        assert_eq!(p.values[2], 0); // RTC fast instruction alias
        assert_eq!((p.values[4] >> 11) & 15, 0b1111); // fast data RW
        assert_eq!(p.values[5], 0); // slow DPORT alias denied
        assert_eq!((p.values[6] >> 11) & 7, 0b110); // primary slow RW, no F
        assert_eq!((p.values[6] >> 14) & 7, 0b110);
        assert_eq!(p.values[7], 0); // secondary slow alias denied
    }

    #[test]
    fn installs_reads_back_then_locks_all_buses_without_changing_other_bits() {
        let mut r = FakeRegisters::default();
        for (offset, mask) in PERMISSIONS {
            r.words[offset / 4] = !mask;
        }
        for offset in MONITORS {
            r.words[offset / 4] = 4; // clear stale fault before enabling
        }
        configure(&mut r, &policy()).unwrap();
        assert!(matches_policy(&r, &policy()));
        for (offset, mask) in PERMISSIONS {
            assert_eq!(r.read(offset) & !mask, !mask);
        }
        assert_eq!(
            &r.writes[r.writes.len() - 4..],
            &LOCKS.map(|offset| (offset, 1))
        );
    }

    #[test]
    fn permission_or_monitor_readback_failure_never_locks() {
        for offset in PERMISSIONS
            .iter()
            .map(|&(offset, _)| offset)
            .chain(MONITORS)
        {
            let mut r = FakeRegisters {
                ignore_write: Some(offset),
                ..Default::default()
            };
            r.words[offset / 4] = u32::MAX;
            assert_eq!(configure(&mut r, &policy()), Err(Error::Readback));
            assert!(!r.writes.iter().any(|(offset, _)| LOCKS.contains(offset)));
        }
    }

    #[test]
    fn failed_lock_is_rejected() {
        for offset in LOCKS {
            let mut r = FakeRegisters {
                ignore_write: Some(offset),
                ..Default::default()
            };
            assert_eq!(configure(&mut r, &policy()), Err(Error::Readback));
        }
    }

    #[test]
    fn partial_or_incompatible_inherited_locks_are_never_modified() {
        for offset in LOCKS {
            let mut r = FakeRegisters::default();
            r.words[offset / 4] = 1;
            assert_eq!(configure(&mut r, &policy()), Err(Error::LockedPolicy));
            assert!(r.writes.is_empty());
        }
        let mut r = FakeRegisters::default();
        configure(&mut r, &policy()).unwrap();
        r.writes.clear();
        assert_eq!(
            configure(&mut r, &Policy::new(0x4002_9000, 0x3ffb_9000).unwrap()),
            Err(Error::LockedPolicy)
        );
        assert!(r.writes.is_empty());
    }

    #[test]
    fn compatible_inherited_policy_is_accepted_without_writes() {
        let mut r = FakeRegisters::default();
        configure(&mut r, &policy()).unwrap();
        r.writes.clear();
        configure(&mut r, &policy()).unwrap();
        assert!(r.writes.is_empty());
        // Even a compatible locked policy must not ignore a pending fault.
        r.words[MONITORS[0] / 4] |= 4;
        assert_eq!(configure(&mut r, &policy()), Err(Error::LockedPolicy));
        assert!(r.writes.is_empty());
    }

    #[test]
    fn status_contains_only_layout_permissions_and_flags() {
        let mut r = FakeRegisters::default();
        configure(&mut r, &policy()).unwrap();
        r.words[0x24 / 4] = 0xdead_beef; // raw fault address must not escape
        r.words[MONITORS[2] / 4] |= 4;
        r.writes.clear();
        let mut output = [0xff; RESPONSE_SIZE];
        assert_eq!(encode_status(&r, &policy(), &mut output), RESPONSE_SIZE);
        assert_eq!(&output[..8], b"RKMP\x01\x0f\x0f\x04");
        assert_eq!(&output[48..], &[0; 16]);
        assert!(!output.windows(4).any(|w| w == 0xdead_beefu32.to_le_bytes()));
        assert!(r.writes.is_empty());
    }
}
