#![no_std]
#![no_main]

use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    delay::Delay,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    main,
    time::Instant,
};
use esp_storage::FlashStorage;
use littlefs2::{
    consts::{U1, U256},
    driver::Storage,
    fs::Allocation,
    io::{Error, Result},
    path,
};

use salpa::platform::{
    attestation,
    storage::{mount_existing, verify_storage_version},
    storage_layout::{ERASE_SIZE, FIDO_STORE_BLOCK_COUNT, checked_absolute_range},
};

const REQUIRED_HOLD_MS: u64 = 5_000;
const CUT_WINDOW_MS: u32 = 120_000;
const STAGE_PATH: &littlefs2::path::Path = path!("/.rissokey-powercut-stage");
const RECORD_PATH: &littlefs2::path::Path = path!("/.rissokey-powercut-record");
const PROGRAM_ARMED: &[u8] = b"program-armed-v1\n";
const ERASE_ARMED: &[u8] = b"erase-armed-v1\n";
const OLD_RECORD: &[u8] = b"old-complete-record-0123456789abcdef\n";
const NEW_RECORD: &[u8] = b"new-complete-record-fedcba9876543210\n";

esp_bootloader_esp_idf::esp_app_desc!();

#[derive(Clone, Copy, PartialEq)]
enum FaultKind {
    None,
    Program,
    Erase,
}

struct PowerCutStorage {
    flash: FlashStorage<'static>,
    led: Output<'static>,
    fault: FaultKind,
    triggered: bool,
}

impl PowerCutStorage {
    fn new(flash: esp_hal::peripherals::FLASH<'static>, led: Output<'static>) -> Self {
        Self {
            flash: FlashStorage::new(flash),
            led,
            fault: FaultKind::None,
            triggered: false,
        }
    }

    fn arm(&mut self, fault: FaultKind) {
        assert!(self.fault == FaultKind::None && !self.triggered);
        self.fault = fault;
    }

    fn absolute_range(offset: usize, len: usize) -> Result<(u32, u32)> {
        checked_absolute_range(offset, len).ok_or(Error::IO)
    }

    fn cut_window(&mut self) {
        self.triggered = true;
        self.led.set_high();
        Delay::new().delay_millis(CUT_WINDOW_MS);
    }

    fn led(&mut self) -> &mut Output<'static> {
        &mut self.led
    }
}

impl Storage for PowerCutStorage {
    const READ_SIZE: usize = 4;
    const WRITE_SIZE: usize = 4;
    const BLOCK_SIZE: usize = ERASE_SIZE;
    const BLOCK_COUNT: usize = FIDO_STORE_BLOCK_COUNT;
    const BLOCK_CYCLES: isize = 500;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U1;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<usize> {
        let (start, _) = Self::absolute_range(offset, buffer.len())?;
        ReadNorFlash::read(&mut self.flash, start, buffer).map_err(|_| Error::IO)?;
        Ok(buffer.len())
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        let (start, _) = Self::absolute_range(offset, data.len())?;
        if self.fault == FaultKind::Program && !self.triggered && data.len() >= 8 {
            let split = ((data.len() / 2) / Self::WRITE_SIZE) * Self::WRITE_SIZE;
            NorFlash::write(&mut self.flash, start, &data[..split]).map_err(|_| Error::IO)?;
            self.cut_window();
            NorFlash::write(
                &mut self.flash,
                start + u32::try_from(split).map_err(|_| Error::IO)?,
                &data[split..],
            )
            .map_err(|_| Error::IO)?;
        } else {
            NorFlash::write(&mut self.flash, start, data).map_err(|_| Error::IO)?;
        }
        Ok(data.len())
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<usize> {
        let (start, end) = Self::absolute_range(offset, len)?;
        NorFlash::erase(&mut self.flash, start, end).map_err(|_| Error::IO)?;
        if self.fault == FaultKind::Erase && !self.triggered {
            self.cut_window();
        }
        Ok(len)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Start,
    ProgramArmed,
    EraseArmed,
    Invalid,
}

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    );
    let led = Output::new(peripherals.GPIO15, Level::Low, OutputConfig::default());
    let mut storage = PowerCutStorage::new(peripherals.FLASH, led);

    let stage = {
        let mut allocation = Allocation::new();
        let filesystem = match mount_existing(&mut allocation, &mut storage) {
            Ok(filesystem) => filesystem,
            Err(_) => failure(storage.led()),
        };
        if verify_storage_version(&filesystem).is_err()
            || attestation::verify_development_attestation(&filesystem).is_err()
        {
            failure(storage.led());
        }
        read_stage(&filesystem)
    };

    match stage {
        Stage::Start => run_program_test(&button, &mut storage),
        Stage::ProgramArmed => {
            verify_record(&mut storage);
            wait_for_hold(&button, storage.led(), Signal::ProgramRecovered);
            run_erase_test(&mut storage);
        }
        Stage::EraseArmed => {
            verify_record(&mut storage);
            cleanup(&mut storage);
            success(storage.led());
        }
        Stage::Invalid => failure(storage.led()),
    }
}

fn read_stage<S: Storage>(filesystem: &littlefs2::fs::Filesystem<'_, S>) -> Stage {
    if !filesystem.exists(STAGE_PATH) {
        return Stage::Start;
    }
    match filesystem.read::<32>(STAGE_PATH) {
        Ok(value) if value.as_slice() == PROGRAM_ARMED => Stage::ProgramArmed,
        Ok(value) if value.as_slice() == ERASE_ARMED => Stage::EraseArmed,
        _ => Stage::Invalid,
    }
}

fn run_program_test(button: &Input<'_>, storage: &mut PowerCutStorage) -> ! {
    wait_for_hold(button, storage.led(), Signal::Initial);
    {
        let mut allocation = Allocation::new();
        let filesystem = mount_existing(&mut allocation, storage).unwrap_or_else(|_| failure_raw());
        filesystem
            .write(RECORD_PATH, OLD_RECORD)
            .unwrap_or_else(|_| failure_raw());
        filesystem
            .write(STAGE_PATH, PROGRAM_ARMED)
            .unwrap_or_else(|_| failure_raw());
        let record = filesystem
            .read::<64>(RECORD_PATH)
            .unwrap_or_else(|_| failure_raw());
        if record.as_slice() != OLD_RECORD {
            failure_raw();
        }
    }
    storage.arm(FaultKind::Program);
    let mut allocation = Allocation::new();
    let filesystem = mount_existing(&mut allocation, storage).unwrap_or_else(|_| failure_raw());
    filesystem
        .write(RECORD_PATH, NEW_RECORD)
        .unwrap_or_else(|_| failure_raw());
    failure_raw()
}

fn run_erase_test(storage: &mut PowerCutStorage) -> ! {
    {
        let mut allocation = Allocation::new();
        let filesystem = mount_existing(&mut allocation, storage).unwrap_or_else(|_| failure_raw());
        filesystem
            .write(STAGE_PATH, ERASE_ARMED)
            .unwrap_or_else(|_| failure_raw());
        filesystem
            .write(RECORD_PATH, OLD_RECORD)
            .unwrap_or_else(|_| failure_raw());
    }
    storage.arm(FaultKind::Erase);
    let mut allocation = Allocation::new();
    let filesystem = mount_existing(&mut allocation, storage).unwrap_or_else(|_| failure_raw());
    for index in 0..4_000 {
        let record = if index % 2 == 0 {
            NEW_RECORD
        } else {
            OLD_RECORD
        };
        filesystem
            .write(RECORD_PATH, record)
            .unwrap_or_else(|_| failure_raw());
    }
    failure_raw()
}

fn verify_record(storage: &mut PowerCutStorage) {
    let mut allocation = Allocation::new();
    let filesystem = mount_existing(&mut allocation, storage).unwrap_or_else(|_| failure_raw());
    if attestation::verify_development_attestation(&filesystem).is_err() {
        failure_raw();
    }
    let record = filesystem
        .read::<64>(RECORD_PATH)
        .unwrap_or_else(|_| failure_raw());
    if record.as_slice() != OLD_RECORD && record.as_slice() != NEW_RECORD {
        failure_raw();
    }
}

fn cleanup(storage: &mut PowerCutStorage) {
    let mut allocation = Allocation::new();
    let filesystem = mount_existing(&mut allocation, storage).unwrap_or_else(|_| failure_raw());
    filesystem
        .remove(RECORD_PATH)
        .unwrap_or_else(|_| failure_raw());
    filesystem
        .remove(STAGE_PATH)
        .unwrap_or_else(|_| failure_raw());
}

#[derive(Clone, Copy)]
enum Signal {
    Initial,
    ProgramRecovered,
}

fn wait_for_hold(button: &Input<'_>, led: &mut Output<'_>, signal: Signal) {
    let delay = Delay::new();
    let mut gesture = salpa::platform::provisioning::ProvisioningGesture::new(REQUIRED_HOLD_MS);
    loop {
        let pressed = button.is_low();
        if pressed {
            led.set_high();
            if gesture.sample(pressed, Instant::now().duration_since_epoch().as_millis()) {
                led.set_low();
                while button.is_low() {}
                return;
            }
        } else {
            gesture.sample(pressed, Instant::now().duration_since_epoch().as_millis());
            match signal {
                Signal::Initial => led.set_low(),
                Signal::ProgramRecovered => {
                    led.set_high();
                    delay.delay_millis(100);
                    led.set_low();
                    delay.delay_millis(100);
                    led.set_high();
                    delay.delay_millis(100);
                    led.set_low();
                    delay.delay_millis(700);
                }
            }
        }
    }
}

fn success(led: &mut Output<'_>) -> ! {
    let delay = Delay::new();
    loop {
        led.set_high();
        delay.delay_millis(100);
        led.set_low();
        delay.delay_millis(100);
    }
}

fn failure(led: &mut Output<'_>) -> ! {
    let delay = Delay::new();
    loop {
        led.set_high();
        delay.delay_millis(1_000);
        led.set_low();
        delay.delay_millis(1_000);
    }
}

fn failure_raw() -> ! {
    panic!("physical storage fault test failed")
}
