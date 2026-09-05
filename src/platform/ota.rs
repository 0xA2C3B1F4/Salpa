//! Minimal ESP-IDF-compatible A/B confirmation at the flash transport boundary.
//!
//! Image delivery and signature verification are handled outside this module.
//! This code only changes the active `otadata` entry from `PENDING_VERIFY` to
//! `VALID` after the running image has completed a successful CTAP2 request.

#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
const OTADATA_OFFSET: u32 = 0xF000;
#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
const OTA_SECTOR_SIZE: u32 = 0x1000;
const OTA_ENTRY_SIZE: usize = 32;
const OTA_SLOT_COUNT: u32 = 2;
const OTA_0_OFFSET: u32 = 0x20000;
const OTA_1_OFFSET: u32 = 0x200000;
#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
const APP_DESCRIPTOR_OFFSET: u32 = 32;
const APP_DESCRIPTOR_SIZE: usize = 256;
const APP_DESCRIPTOR_MAGIC: u32 = 0xABCD5432;
const APP_VERSION_OFFSET: usize = 16;
const APP_VERSION_SIZE: usize = 32;

const OTA_STATE_PENDING_VERIFY: u32 = 1;
const OTA_STATE_VALID: u32 = 2;
const OTA_STATE_INVALID: u32 = 3;
const OTA_STATE_ABORTED: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OtaEntry {
    sequence: u32,
    state: u32,
    crc: u32,
}

impl OtaEntry {
    fn decode(bytes: &[u8; OTA_ENTRY_SIZE]) -> Self {
        Self {
            sequence: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            state: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            crc: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        }
    }

    fn is_selectable(self) -> bool {
        self.sequence != u32::MAX
            && self.state != OTA_STATE_INVALID
            && self.state != OTA_STATE_ABORTED
            && self.crc == ota_crc(self.sequence)
    }

    fn encode_with_state(self, state: u32) -> [u8; OTA_ENTRY_SIZE] {
        let mut bytes = [0xff; OTA_ENTRY_SIZE];
        bytes[0..4].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[24..28].copy_from_slice(&state.to_le_bytes());
        bytes[28..32].copy_from_slice(&ota_crc(self.sequence).to_le_bytes());
        bytes
    }
}

fn active_entry(entries: [OtaEntry; 2]) -> Option<usize> {
    match (entries[0].is_selectable(), entries[1].is_selectable()) {
        (true, true) if entries[0].sequence >= entries[1].sequence => Some(0),
        (true, true) => Some(1),
        (true, false) => Some(0),
        (false, true) => Some(1),
        (false, false) => None,
    }
}

fn update_layout_from_entries(entries: [OtaEntry; 2]) -> Option<(u8, u32, u8)> {
    let active = active_entry(entries)?;
    if entries[active].state != OTA_STATE_VALID {
        return None;
    }
    let sequence = entries[active].sequence;
    let slot = u8::try_from(sequence.checked_sub(1)? % OTA_SLOT_COUNT).ok()?;
    Some((slot, sequence, (1 - active) as u8))
}

fn activation_is_valid(
    active_slot: u8,
    active_sequence: u32,
    expected_entry: u8,
    target_slot: u8,
    sequence: u32,
    activation_entry: u8,
) -> bool {
    target_slot <= 1
        && activation_entry <= 1
        && target_slot != active_slot
        && activation_entry == expected_entry
        && sequence
            .checked_sub(1)
            .map(|value| (value % OTA_SLOT_COUNT) as u8)
            == Some(target_slot)
        && sequence > active_sequence
}

fn slot_offset(sequence: u32) -> Option<u32> {
    match sequence.checked_sub(1)? % OTA_SLOT_COUNT {
        0 => Some(OTA_0_OFFSET),
        1 => Some(OTA_1_OFFSET),
        _ => None,
    }
}

fn descriptor_matches_version(descriptor: &[u8; APP_DESCRIPTOR_SIZE], version: &str) -> bool {
    if u32::from_le_bytes(descriptor[0..4].try_into().unwrap()) != APP_DESCRIPTOR_MAGIC {
        return false;
    }
    let expected = version.as_bytes();
    if expected.is_empty() || expected.len() >= APP_VERSION_SIZE {
        return false;
    }
    let field = &descriptor[APP_VERSION_OFFSET..APP_VERSION_OFFSET + APP_VERSION_SIZE];
    field[..expected.len()] == *expected && field[expected.len()] == 0
}

fn ota_crc(sequence: u32) -> u32 {
    let mut crc = 0_u32;
    for byte in sequence.to_le_bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmError {
    FlashRead,
    FlashUnlock,
    FlashErase,
    FlashWrite,
    ReadbackMismatch,
    InvalidLayout,
}

#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
#[repr(align(4))]
struct Aligned<const N: usize>([u8; N]);

#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
fn read_flash<const N: usize>(address: u32, output: &mut Aligned<N>) -> Result<(), ConfirmError> {
    #[cfg(feature = "release-flash-encryption")]
    {
        super::flash_encryption::read(address, &mut output.0).map_err(|_| ConfirmError::FlashRead)
    }

    #[cfg(not(feature = "release-flash-encryption"))]
    {
        unsafe { esp_storage::ll::spiflash_read(address, output.0.as_mut_ptr().cast(), N as u32) }
            .map_err(|_| ConfirmError::FlashRead)
    }
}

#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
fn replace_entry(address: u32, replacement: &Aligned<OTA_ENTRY_SIZE>) -> Result<(), ConfirmError> {
    #[cfg(feature = "release-flash-encryption")]
    {
        super::flash_encryption::erase(address, OTA_SECTOR_SIZE as usize)
            .map_err(|_| ConfirmError::FlashErase)?;
        super::flash_encryption::write(address, &replacement.0)
            .map_err(|_| ConfirmError::FlashWrite)
    }

    #[cfg(not(feature = "release-flash-encryption"))]
    {
        use esp_storage::ll::{spiflash_erase_sector, spiflash_unlock, spiflash_write};

        unsafe { spiflash_unlock() }.map_err(|_| ConfirmError::FlashUnlock)?;
        unsafe { spiflash_erase_sector(address / OTA_SECTOR_SIZE) }
            .map_err(|_| ConfirmError::FlashErase)?;
        unsafe {
            spiflash_write(
                address,
                replacement.0.as_ptr().cast(),
                OTA_ENTRY_SIZE as u32,
            )
        }
        .map_err(|_| ConfirmError::FlashWrite)
    }
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
fn read_entries() -> Result<([OtaEntry; 2], usize), ConfirmError> {
    let mut raw_entries = [
        Aligned([0_u8; OTA_ENTRY_SIZE]),
        Aligned([0_u8; OTA_ENTRY_SIZE]),
    ];
    for (index, raw) in raw_entries.iter_mut().enumerate() {
        read_flash(OTADATA_OFFSET + index as u32 * OTA_SECTOR_SIZE, raw)?;
    }
    let entries = [
        OtaEntry::decode(&raw_entries[0].0),
        OtaEntry::decode(&raw_entries[1].0),
    ];
    let active = active_entry(entries).ok_or(ConfirmError::InvalidLayout)?;
    Ok((entries, active))
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
pub fn update_layout() -> Result<crate::usb_update::UpdateLayout, ConfirmError> {
    let (entries, active) = read_entries()?;
    let (slot, sequence, activation_entry) =
        update_layout_from_entries(entries).ok_or(ConfirmError::InvalidLayout)?;
    debug_assert_eq!(active as u8, 1 - activation_entry);
    Ok(crate::usb_update::UpdateLayout {
        active_slot: slot,
        active_sequence: sequence,
        activation_entry,
    })
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
pub fn activate_update(
    target_slot: u8,
    sequence: u32,
    activation_entry: u8,
) -> Result<(), ConfirmError> {
    let layout = update_layout()?;
    if !activation_is_valid(
        layout.active_slot,
        layout.active_sequence,
        layout.activation_entry,
        target_slot,
        sequence,
        activation_entry,
    ) {
        return Err(ConfirmError::InvalidLayout);
    }
    let replacement = Aligned(
        OtaEntry {
            sequence,
            state: 0,
            crc: ota_crc(sequence),
        }
        .encode_with_state(0),
    );
    let entry_address = OTADATA_OFFSET + u32::from(activation_entry) * OTA_SECTOR_SIZE;
    replace_entry(entry_address, &replacement)?;
    let mut readback = Aligned([0_u8; OTA_ENTRY_SIZE]);
    read_flash(entry_address, &mut readback)?;
    if readback.0 != replacement.0 {
        return Err(ConfirmError::ReadbackMismatch);
    }
    Ok(())
}

#[cfg(feature = "usb-signed-update")]
pub const fn update_slot_offset(slot: u8) -> Option<u32> {
    match slot {
        0 => Some(OTA_0_OFFSET),
        1 => Some(OTA_1_OFFSET),
        _ => None,
    }
}

/// Confirm a pending A/B image only if the active slot's app descriptor matches
/// this running binary. A fallback image therefore cannot accidentally confirm
/// a rejected candidate whose `otadata` entry still has the highest sequence.
#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
pub fn confirm_running_image(version: &str) -> Result<bool, ConfirmError> {
    let mut raw_entries = [
        Aligned([0_u8; OTA_ENTRY_SIZE]),
        Aligned([0_u8; OTA_ENTRY_SIZE]),
    ];
    for (index, raw) in raw_entries.iter_mut().enumerate() {
        read_flash(OTADATA_OFFSET + index as u32 * OTA_SECTOR_SIZE, raw)?;
    }
    let entries = [
        OtaEntry::decode(&raw_entries[0].0),
        OtaEntry::decode(&raw_entries[1].0),
    ];
    let Some(active) = active_entry(entries) else {
        return Ok(false);
    };
    let entry = entries[active];
    if entry.state != OTA_STATE_PENDING_VERIFY {
        return Ok(false);
    }

    let Some(app_offset) = slot_offset(entry.sequence) else {
        return Ok(false);
    };
    let mut descriptor = Aligned([0_u8; APP_DESCRIPTOR_SIZE]);
    read_flash(app_offset + APP_DESCRIPTOR_OFFSET, &mut descriptor)?;
    if !descriptor_matches_version(&descriptor.0, version) {
        return Ok(false);
    }

    let replacement = Aligned(entry.encode_with_state(OTA_STATE_VALID));
    let entry_address = OTADATA_OFFSET + active as u32 * OTA_SECTOR_SIZE;
    replace_entry(entry_address, &replacement)?;

    let mut readback = Aligned([0_u8; OTA_ENTRY_SIZE]);
    read_flash(entry_address, &mut readback)?;
    if readback.0 != replacement.0 {
        return Err(ConfirmError::ReadbackMismatch);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sequence: u32, state: u32) -> OtaEntry {
        OtaEntry {
            sequence,
            state,
            crc: ota_crc(sequence),
        }
    }

    #[test]
    fn crc_matches_pinned_esp_idf_vectors() {
        assert_eq!(ota_crc(1), 0x4743_989a);
        assert_eq!(ota_crc(2), 0x55f6_3774);
        assert_eq!(ota_crc(5), 0xc821_0fcd);
    }

    #[test]
    fn active_entry_matches_esp_idf_max_sequence_rule() {
        assert_eq!(
            active_entry([entry(1, OTA_STATE_VALID), entry(2, 0)]),
            Some(1)
        );
        assert_eq!(
            active_entry([entry(3, OTA_STATE_VALID), entry(2, 0)]),
            Some(0)
        );
        assert_eq!(
            active_entry([entry(3, OTA_STATE_ABORTED), entry(2, 0)]),
            Some(1)
        );
    }

    #[test]
    fn rollback_marks_candidate_aborted_and_reselects_previous_valid_slot() {
        let previous = entry(1, OTA_STATE_VALID);
        let candidate = entry(2, 0);
        assert_eq!(active_entry([previous, candidate]), Some(1));
        assert_eq!(
            active_entry([previous, entry(2, OTA_STATE_ABORTED)]),
            Some(0)
        );
        assert_eq!(
            update_layout_from_entries([previous, entry(2, OTA_STATE_ABORTED)]),
            Some((0, 1, 1))
        );
    }

    #[test]
    fn pending_candidate_cannot_be_replaced_before_first_boot_confirmation() {
        assert_eq!(
            update_layout_from_entries([entry(1, OTA_STATE_VALID), entry(2, 0)]),
            None
        );
    }

    #[test]
    fn activation_contract_requires_inactive_slot_newer_sequence_and_other_entry() {
        assert!(activation_is_valid(0, 1, 1, 1, 2, 1));
        assert!(!activation_is_valid(0, 1, 1, 0, 3, 1));
        assert!(!activation_is_valid(0, 1, 1, 1, 1, 1));
        assert!(!activation_is_valid(0, 1, 1, 1, 2, 0));
    }

    #[test]
    fn sequence_selects_expected_slot() {
        assert_eq!(slot_offset(1), Some(OTA_0_OFFSET));
        assert_eq!(slot_offset(2), Some(OTA_1_OFFSET));
        assert_eq!(slot_offset(3), Some(OTA_0_OFFSET));
        assert_eq!(slot_offset(0), None);
    }

    #[test]
    fn app_descriptor_version_must_match_exactly() {
        let mut descriptor = [0_u8; APP_DESCRIPTOR_SIZE];
        descriptor[..4].copy_from_slice(&APP_DESCRIPTOR_MAGIC.to_le_bytes());
        descriptor[APP_VERSION_OFFSET..APP_VERSION_OFFSET + 5].copy_from_slice(b"0.1.2");
        assert!(descriptor_matches_version(&descriptor, "0.1.2"));
        assert!(!descriptor_matches_version(&descriptor, "0.1"));
        assert!(!descriptor_matches_version(&descriptor, "0.1.3"));
    }

    #[test]
    fn state_rewrite_preserves_sequence_and_crc_contract() {
        let encoded = entry(4, OTA_STATE_PENDING_VERIFY).encode_with_state(OTA_STATE_VALID);
        let decoded = OtaEntry::decode(&encoded);
        assert_eq!(decoded, entry(4, OTA_STATE_VALID));
        assert!(decoded.is_selectable());
    }
}
