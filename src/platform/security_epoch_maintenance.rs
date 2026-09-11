//! Explicit maintenance requests for a fixed, separately signed counter plan.
//!
//! Inspect and rehearsal never program eFuses. Programming requires its own
//! request bound to the plan and both image digests, followed by a fresh long
//! hold and release. Normal firmware does not compile this module.

use core::cell::RefCell;
use sha2::{Digest, Sha256};

use super::{
    ota::{self, QualifiedLayout},
    s2_epoch_programmer,
    s2_user_presence::{self, UserPresenceWaitHook, WemosS2MiniUserHardware},
    security_epoch::{self, ApprovedPlan, ObservedState, PreparedChange, SlotEvidence},
    security_epoch_plan, usb_update,
};
use crate::usb_update::{Phase, verify_installed_slot};

const INSPECT: u8 = 0x13;
const PROGRAM: u8 = 0x14;
const REHEARSE: u8 = 0x15;
const SCOPE: &[u8; security_epoch_plan::PLAN_BYTES] =
    include_bytes!(concat!(env!("OUT_DIR"), "/epoch-plan.bin"));

#[repr(u8)]
#[derive(Clone, Copy)]
enum Error {
    Request = 1,
    Busy = 2,
    Plan = 3,
    Image = 4,
    Presence = 5,
    Transaction = 6,
    Binding = 7,
    Cancelled = 8,
}

struct Qualified {
    change: PreparedChange,
    layout: QualifiedLayout,
    raw: u16,
}

fn bootloader_ciphertext_digest() -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u32; 256];
    for offset in (0x1000..0xd000).step_by(1024) {
        // Fixed, aligned bootloader range and aligned RAM destination. This is
        // the raw SPI read path, not the decrypted application mapping.
        unsafe { esp_storage::ll::spiflash_read(offset, buffer.as_mut_ptr(), 1024) }
            .map_err(|_| Error::Binding)?;
        for word in buffer {
            hash.update(word.to_le_bytes());
        }
    }
    Ok(hash.finalize().into())
}

fn qualify(descriptor: u32, expected: Option<[[u8; 32]; 2]>) -> Result<Qualified, Error> {
    let scope = security_epoch_plan::decode(SCOPE).ok_or(Error::Plan)?;
    if esp_hal::efuse::major_chip_version() != scope.revision_major
        || esp_hal::efuse::minor_chip_version() != scope.revision_minor
    {
        return Err(Error::Binding);
    }
    let before = s2_epoch_programmer::snapshot();
    if before.repeat_errors != [0; 5] {
        return Err(Error::Binding);
    }
    let layout = ota::qualified_layout(descriptor).map_err(|_| Error::Image)?;
    let root = usb_update::trusted_update_key_digest();
    let mut backend = usb_update::Esp32S2UpdateBackend::new(descriptor);
    let mut slots = [SlotEvidence {
        signature_verified: false,
        metadata_valid: false,
        secure_version: 0,
        signed_content_digest: [0; 32],
    }; 2];
    for (index, slot) in slots.iter_mut().enumerate() {
        let image =
            verify_installed_slot(&mut backend, index as u8, &root).map_err(|_| Error::Image)?;
        *slot = SlotEvidence {
            signature_verified: true,
            metadata_valid: true,
            secure_version: image.secure_version,
            signed_content_digest: image.signed_content_digest,
        };
    }
    if slots[usize::from(1 - layout.running_slot)].signed_content_digest != scope.fallback_digest {
        return Err(Error::Binding);
    }
    let observed = ObservedState {
        device_digest: Sha256::digest(esp_hal::efuse::base_mac_address().as_bytes()).into(),
        bootloader_digest: bootloader_ciphertext_digest()?,
        trusted_root_digest: root,
        block0: before.block0,
        running_slot: layout.running_slot,
        slots,
    };
    let plan = ApprovedPlan {
        device_digest: scope.device_digest,
        bootloader_digest: scope.bootloader_digest,
        trusted_root_digest: scope.trusted_root_digest,
        expected_block0: scope.expected_block0,
        qualified_image_digests: expected.unwrap_or(slots.map(|slot| slot.signed_content_digest)),
        target_epoch: scope.target_epoch,
    };
    let change = security_epoch::prepare(&plan, &observed).map_err(|_| Error::Binding)?;
    if ota::qualified_layout(descriptor).map_err(|_| Error::Image)? != layout
        || s2_epoch_programmer::snapshot() != before
    {
        return Err(Error::Binding);
    }
    Ok(Qualified {
        change,
        layout,
        raw: security_epoch::secure_version_raw(&before.block0),
    })
}

pub fn handle(
    request: &[u8],
    descriptor: u32,
    phase: Phase,
    hardware: &RefCell<WemosS2MiniUserHardware>,
    wait_hook: &dyn UserPresenceWaitHook,
    output: &mut [u8; 64],
) -> Option<usize> {
    if !matches!(
        request.first(),
        Some(&INSPECT) | Some(&PROGRAM) | Some(&REHEARSE)
    ) {
        return None;
    }
    output.fill(0);
    output[..4].copy_from_slice(b"RKM1");
    let plan_digest: [u8; 32] = Sha256::digest(SCOPE).into();
    let result = (|| {
        if phase != Phase::Idle {
            return Err(Error::Busy);
        }
        let expected =
            security_epoch_plan::requested_images(request, &plan_digest).ok_or(Error::Request)?;
        let first = qualify(descriptor, expected)?;
        let qualified = if expected.is_some() {
            if !s2_user_presence::confirm_maintenance_user_presence(hardware, wait_hook) {
                return Err(Error::Presence);
            }
            // Physical approval does not excuse stale images or eFuse state.
            let second = qualify(descriptor, expected)?;
            if first.layout != second.layout {
                return Err(Error::Binding);
            }
            wait_hook.poll_wait();
            if wait_hook.cancelled() {
                return Err(Error::Cancelled);
            }
            second
        } else {
            first
        };
        let target = qualified.change.target_epoch();
        let delta = qualified.change.bits_to_program();
        if request[0] == PROGRAM {
            s2_epoch_programmer::attempt(qualified.change).map_err(|error| {
                output[5] = error.status_code();
                Error::Transaction
            })?;
        }
        output[5] = target;
        output[6] = qualified.layout.running_slot;
        output[7] = qualified.raw.count_ones() as u8;
        output[8..40].copy_from_slice(&plan_digest);
        output[40..44].copy_from_slice(&qualified.layout.sequences[0].to_le_bytes());
        output[44..48].copy_from_slice(&qualified.layout.sequences[1].to_le_bytes());
        output[48..52].copy_from_slice(
            &esp_hal::clock::Clocks::get()
                .apb_clock
                .as_hz()
                .to_le_bytes(),
        );
        output[52..54].copy_from_slice(&qualified.raw.to_le_bytes());
        output[54..56].copy_from_slice(&delta.to_le_bytes());
        output[56] = request[0];
        Ok(())
    })();
    if let Err(error) = result {
        output[4] = error as u8;
    }
    Some(64)
}
