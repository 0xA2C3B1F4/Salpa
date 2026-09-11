//! ESP32-S2 BLOCK0 adapter for the separately gated maintenance build.
//!
//! ROM ABI and registers follow ESP-IDF fff9895c82d744c7237be8847347bdd1b07c6643.
//! No key blocks or policy-lock fields can be selected by this adapter.

use super::{
    security_epoch::PreparedChange,
    security_epoch_transaction::{
        Backend, Snapshot, Transaction, TransactionError, controller_commands_idle,
    },
};
use core::cell::Cell;
use critical_section::Mutex;

const BASE: usize = 0x3f41_a000;
const ERROR_OFFSETS: [usize; 5] = [0x17c, 0x180, 0x184, 0x188, 0x190];
static ATTEMPTED: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));

unsafe extern "C" {
    fn ets_efuse_set_timing(apb_hz: u32) -> i32;
    fn ets_efuse_read() -> i32;
    fn ets_efuse_clear_program_registers();
    fn ets_efuse_program(block: u32) -> i32;
}

fn read(offset: usize) -> u32 {
    // Every caller uses an aligned register in the pinned S2 eFuse peripheral.
    unsafe { core::ptr::read_volatile((BASE + offset) as *const u32) }
}

pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        // WR_DIS is at +0x2c. +0x30 alone would omit the first BLOCK0 word.
        block0: core::array::from_fn(|i| read(0x2c + i * 4)),
        // The final error register is not contiguous with the first four.
        repeat_errors: ERROR_OFFSETS.map(read),
    }
}

struct RomBackend;

impl Backend for RomBackend {
    fn apb_hz(&self) -> u32 {
        esp_hal::clock::Clocks::get().apb_clock.as_hz()
    }

    fn idle(&self) -> bool {
        controller_commands_idle(|| read(0x1d4))
    }

    fn set_timing(&mut self) -> bool {
        // Transaction requires the reviewed fixed 80 MHz APB configuration.
        unsafe { ets_efuse_set_timing(self.apb_hz()) == 0 }
    }

    fn refresh(&mut self) -> bool {
        unsafe { ets_efuse_read() == 0 }
    }

    fn snapshot(&self) -> Snapshot {
        snapshot()
    }

    fn clear_staging(&mut self) {
        unsafe { ets_efuse_clear_program_registers() }
    }

    fn staging(&self) -> [u32; 11] {
        core::array::from_fn(|i| read(i * 4))
    }

    fn stage_counter(&mut self, words: [u32; 8]) {
        // This receives PreparedChange's counter-only delta after zero staging
        // has been verified. Write just PGM_DATA4, leaving all other words zero.
        assert!(
            words
                .iter()
                .enumerate()
                .all(|(i, word)| i == 4 || *word == 0)
        );
        assert_eq!(words[4] & !(0xffff << 11), 0);
        unsafe { core::ptr::write_volatile((BASE + 0x10) as *mut u32, words[4]) }
    }

    fn program_block0(&mut self) -> bool {
        unsafe { ets_efuse_program(0) == 0 }
    }
}

/// The maintenance handler calls this only after fresh long-hold approval and
/// repeated image, identity, bootloader, root and complete BLOCK0 qualification.
/// The per-boot latch and exclusive section cover the entire transaction.
pub(super) fn attempt(change: PreparedChange) -> Result<(), TransactionError> {
    critical_section::with(|cs| {
        if ATTEMPTED.borrow(cs).replace(true) {
            return Err(TransactionError::AlreadyAttempted);
        }
        Transaction::new(RomBackend).attempt(change)
    })
}
