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
const DROM_START: u32 = 0x3f00_0000;
const DROM_APP_END: u32 = 0x3f39_0000;
const MMU_FLASH: u32 = 1 << 15;
const MMU_PAGE_MASK: u32 = 0x3fff;

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

#[cfg(any(feature = "usb-signed-update", test))]
fn update_layout_from_entries(
    entries: [OtaEntry; 2],
    running_offset: u32,
) -> Option<(u8, u32, u8)> {
    let active = active_entry(entries)?;
    if entries[active].state != OTA_STATE_VALID {
        return None;
    }
    let sequence = entries[active].sequence;
    // Hardware anti-rollback can skip a higher-sequence, correctly signed old
    // image without invalidating its metadata. Never let that record label the
    // executing fallback as the inactive slot to erase.
    if slot_offset(sequence)? != running_offset {
        return None;
    }
    let slot = u8::try_from(sequence.checked_sub(1)? % OTA_SLOT_COUNT).ok()?;
    Some((slot, sequence, (1 - active) as u8))
}

/// Both records must qualify different slots, and the selected record must
/// describe the executing image. Merely having two selectable records is
/// insufficient before raising a hardware security floor.
#[cfg(any(feature = "usb-signed-update", test))]
fn qualified_layout_from_entries(
    entries: [OtaEntry; 2],
    running_offset: u32,
) -> Option<QualifiedLayout> {
    let active = active_entry(entries)?;
    let mut sequences = [0; 2];
    for entry in entries {
        if !entry.is_selectable() || entry.state != OTA_STATE_VALID {
            return None;
        }
        let slot = match slot_offset(entry.sequence)? {
            OTA_0_OFFSET => 0,
            OTA_1_OFFSET => 1,
            _ => return None,
        };
        if sequences[slot] != 0 {
            return None;
        }
        sequences[slot] = entry.sequence;
    }
    if slot_offset(entries[active].sequence)? != running_offset {
        return None;
    }
    Some(QualifiedLayout {
        running_slot: ((entries[active].sequence - 1) % OTA_SLOT_COUNT) as u8,
        sequences,
    })
}

#[cfg(any(feature = "usb-signed-update", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualifiedLayout {
    pub running_slot: u8,
    /// Valid metadata sequence for each physical application slot.
    pub sequences: [u32; 2],
}

#[cfg(any(feature = "usb-signed-update", test))]
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

fn running_offset_from_mapping(descriptor_address: u32, mmu_entry: u32) -> Option<u32> {
    // Pinned ESP32-S2 MMU: 64 KiB pages, flash flag at bit 15, invalid at
    // bit 14 and PSRAM at bit 16. Reject every non-flash/unknown flag.
    if !(DROM_START..DROM_APP_END).contains(&descriptor_address)
        || descriptor_address & 0xffff != 32
        || mmu_entry & !MMU_PAGE_MASK != MMU_FLASH
    {
        return None;
    }
    let offset = (mmu_entry & MMU_PAGE_MASK) << 16;
    match offset {
        OTA_0_OFFSET | OTA_1_OFFSET => Some(offset),
        _ => None,
    }
}

#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
fn running_app_offset(descriptor_address: u32) -> Result<u32, ConfirmError> {
    if !(DROM_START..DROM_APP_END).contains(&descriptor_address) {
        return Err(ConfirmError::InvalidLayout);
    }
    // ESP-IDF fff9895: esp32s2 mmu_ll_get_entry_id/read_entry. DROM is IBUS2,
    // whose entries begin at index 0x80 in DR_REG_MMU_TABLE. Read only; never
    // infer the running partition from mutable otadata or a version string.
    let entry_index = 0x80 + ((descriptor_address & 0x3f_ffff) >> 16);
    let entry_address = 0x6180_1000 + entry_index * 4;
    let entry = unsafe { core::ptr::read_volatile(entry_address as *const u32) };
    running_offset_from_mapping(descriptor_address, entry).ok_or(ConfirmError::InvalidLayout)
}

fn confirmation_matches_running_image(
    entry: OtaEntry,
    running_offset: u32,
    descriptor: &[u8; APP_DESCRIPTOR_SIZE],
    version: &str,
    secure_version: u32,
) -> bool {
    entry.state == OTA_STATE_PENDING_VERIFY
        && slot_offset(entry.sequence) == Some(running_offset)
        && descriptor_matches_version(descriptor, version)
        && u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) == secure_version
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
pub fn update_layout(
    descriptor_address: u32,
) -> Result<crate::usb_update::UpdateLayout, ConfirmError> {
    let running_offset = running_app_offset(descriptor_address)?;
    let (entries, active) = read_entries()?;
    let (slot, sequence, activation_entry) =
        update_layout_from_entries(entries, running_offset).ok_or(ConfirmError::InvalidLayout)?;
    debug_assert_eq!(active as u8, 1 - activation_entry);
    Ok(crate::usb_update::UpdateLayout {
        active_slot: slot,
        active_sequence: sequence,
        activation_entry,
    })
}

/// Read-only qualification of both metadata records and the actual DROM map.
/// Callers must separately authenticate both complete installed images.
#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
pub fn qualified_layout(descriptor_address: u32) -> Result<QualifiedLayout, ConfirmError> {
    let running_offset = running_app_offset(descriptor_address)?;
    let (entries, _) = read_entries()?;
    qualified_layout_from_entries(entries, running_offset).ok_or(ConfirmError::InvalidLayout)
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
pub fn activate_update(
    target_slot: u8,
    sequence: u32,
    activation_entry: u8,
    descriptor_address: u32,
) -> Result<(), ConfirmError> {
    let layout = update_layout(descriptor_address)?;
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

/// Confirm only the slot backing the running application's mapped descriptor.
/// A fallback cannot confirm a rejected candidate, including an identical copy
/// or a different build that reused its version string.
#[cfg(all(feature = "signed-ab-update", feature = "mcu-esp32s2", not(test)))]
pub fn confirm_running_image(
    version: &str,
    secure_version: u32,
    descriptor_address: u32,
) -> Result<bool, ConfirmError> {
    let running_offset = running_app_offset(descriptor_address)?;
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
    if !confirmation_matches_running_image(
        entry,
        running_offset,
        &descriptor.0,
        version,
        secure_version,
    ) {
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
    fn maintenance_layout_requires_distinct_valid_slots_and_the_executing_mapping() {
        let entries = [entry(3, OTA_STATE_VALID), entry(4, OTA_STATE_VALID)];
        assert_eq!(
            qualified_layout_from_entries(entries, OTA_1_OFFSET),
            Some(QualifiedLayout {
                running_slot: 1,
                sequences: [3, 4]
            })
        );
        assert_eq!(
            qualified_layout_from_entries([entries[1], entries[0]], OTA_1_OFFSET),
            Some(QualifiedLayout {
                running_slot: 1,
                sequences: [3, 4]
            })
        );
        assert_eq!(qualified_layout_from_entries(entries, OTA_0_OFFSET), None);
        for sequence in [0, 3, 5, u32::MAX] {
            assert_eq!(
                qualified_layout_from_entries(
                    [entries[0], entry(sequence, OTA_STATE_VALID)],
                    OTA_0_OFFSET
                ),
                None
            );
        }
        for state in [
            0,
            OTA_STATE_PENDING_VERIFY,
            OTA_STATE_INVALID,
            OTA_STATE_ABORTED,
            u32::MAX,
        ] {
            for index in 0..2 {
                let mut changed = entries;
                changed[index].state = state;
                assert_eq!(qualified_layout_from_entries(changed, OTA_1_OFFSET), None);
            }
        }
        for index in 0..2 {
            let mut changed = entries;
            changed[index].crc ^= 1;
            assert_eq!(qualified_layout_from_entries(changed, OTA_1_OFFSET), None);
        }
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
            update_layout_from_entries([previous, entry(2, OTA_STATE_ABORTED)], OTA_0_OFFSET),
            Some((0, 1, 1))
        );
    }

    #[test]
    fn pending_candidate_cannot_be_replaced_before_first_boot_confirmation() {
        assert_eq!(
            update_layout_from_entries([entry(1, OTA_STATE_VALID), entry(2, 0)], OTA_1_OFFSET),
            None
        );
    }

    #[test]
    fn hardware_floor_fallback_cannot_offer_the_running_slot_for_update() {
        // Bootloader skips the higher-sequence epoch-4 image, while its VALID
        // metadata survives. Epoch-5 fallback is actually executing in slot 1.
        let entries = [entry(17, OTA_STATE_VALID), entry(16, OTA_STATE_VALID)];
        assert_eq!(active_entry(entries), Some(0));
        assert_eq!(update_layout_from_entries(entries, OTA_1_OFFSET), None);
        assert_eq!(
            update_layout_from_entries([entries[1], entries[0]], OTA_1_OFFSET),
            None
        );
        assert_eq!(
            update_layout_from_entries(entries, OTA_0_OFFSET),
            Some((0, 17, 1))
        );
        let reverse = [entry(17, OTA_STATE_VALID), entry(18, OTA_STATE_VALID)];
        assert_eq!(update_layout_from_entries(reverse, OTA_0_OFFSET), None);
        assert_eq!(update_layout_from_entries(entries, 0), None);
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
    fn fallback_cannot_confirm_an_identically_named_candidate() {
        let mut descriptor = [0_u8; APP_DESCRIPTOR_SIZE];
        descriptor[..4].copy_from_slice(&APP_DESCRIPTOR_MAGIC.to_le_bytes());
        descriptor[4..8].copy_from_slice(&4_u32.to_le_bytes());
        descriptor[APP_VERSION_OFFSET..APP_VERSION_OFFSET + 5].copy_from_slice(b"0.1.0");
        let candidate = entry(3, OTA_STATE_PENDING_VERIFY);
        assert!(confirmation_matches_running_image(
            candidate,
            OTA_0_OFFSET,
            &descriptor,
            "0.1.0",
            4,
        ));
        // Even identical descriptor bytes do not let ota_1 confirm ota_0.
        assert!(!confirmation_matches_running_image(
            candidate,
            OTA_1_OFFSET,
            &descriptor,
            "0.1.0",
            4,
        ));
        assert!(!confirmation_matches_running_image(
            candidate,
            OTA_0_OFFSET,
            &descriptor,
            "0.1.0",
            3,
        ));
        assert!(!confirmation_matches_running_image(
            entry(3, OTA_STATE_ABORTED),
            OTA_0_OFFSET,
            &descriptor,
            "0.1.0",
            4,
        ));
    }

    #[test]
    fn running_slot_requires_a_valid_application_drom_flash_mapping() {
        assert_eq!(
            running_offset_from_mapping(0x3f00_0020, 0x8002),
            Some(OTA_0_OFFSET)
        );
        assert_eq!(
            running_offset_from_mapping(0x3f00_0020, 0x8020),
            Some(OTA_1_OFFSET)
        );
        for invalid in [
            0x0002,
            0xc002,
            0x10002,
            0x18002,
            0x8000,
            0x803e,
            0x8000_8002,
        ] {
            assert_eq!(running_offset_from_mapping(0x3f00_0020, invalid), None);
        }
        for address in [0, 0x3f00_0000, 0x3f00_0021, 0x3f39_0020, 0x4008_0020] {
            assert_eq!(running_offset_from_mapping(address, 0x8002), None);
        }
    }

    #[test]
    fn state_rewrite_preserves_sequence_and_crc_contract() {
        let encoded = entry(4, OTA_STATE_PENDING_VERIFY).encode_with_state(OTA_STATE_VALID);
        let decoded = OtaEntry::decode(&encoded);
        assert_eq!(decoded, entry(4, OTA_STATE_VALID));
        assert!(decoded.is_selectable());
    }

    #[test]
    fn interrupted_metadata_write_retains_the_other_valid_entry() {
        // Model a lost write after each byte of the replacement record. This
        // checks selection from partially programmed plaintext records, not
        // the electrical behavior of encrypted flash during a power cut.
        for state in [0, OTA_STATE_PENDING_VERIFY, OTA_STATE_VALID] {
            for replacement_index in 0..2 {
                let previous = entry(2, OTA_STATE_VALID);
                let replacement = entry(3, state).encode_with_state(state);
                for written in 0..=OTA_ENTRY_SIZE {
                    let mut partial = [0xff; OTA_ENTRY_SIZE];
                    partial[..written].copy_from_slice(&replacement[..written]);
                    let mut entries = [previous; 2];
                    entries[replacement_index] = OtaEntry::decode(&partial);
                    let expected = if written == OTA_ENTRY_SIZE {
                        replacement_index
                    } else {
                        1 - replacement_index
                    };
                    assert_eq!(active_entry(entries), Some(expected));
                }
            }
        }
    }
}
