//! Read-only installed-image checks for the separate epoch-preview build.
//!
//! The response contains firmware digests and OTA metadata only. No key blocks,
//! device identifiers, credential data or eFuse programming registers are read.

use crate::{
    platform::ota::QualifiedLayout,
    usb_update::{Phase, VerifiedInstalledImage},
};

pub const REQUEST: u8 = 0x12;
pub const RESPONSE_SIZE: usize = 64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewError {
    Busy = 1,
    Layout = 2,
    Image = 3,
    Request = 4,
}

fn requested_slot(request: &[u8], phase: Phase) -> Result<u8, PreviewError> {
    if request.len() != 2 || request[0] != REQUEST || request[1] > 1 {
        return Err(PreviewError::Request);
    }
    if phase != Phase::Idle {
        return Err(PreviewError::Busy);
    }
    Ok(request[1])
}

fn encode(
    slot: u8,
    result: Result<(QualifiedLayout, VerifiedInstalledImage), PreviewError>,
    output: &mut [u8; 64],
) -> usize {
    output.fill(0);
    output[..4].copy_from_slice(b"RKE1");
    output[5] = slot;
    match result {
        Ok((layout, image)) => {
            output[6] = layout.running_slot;
            output[8..12].copy_from_slice(&image.secure_version.to_le_bytes());
            output[12..16].copy_from_slice(&image.signed_image_bytes.to_le_bytes());
            output[16..48].copy_from_slice(&image.signed_content_digest);
            output[48..52].copy_from_slice(&layout.sequences[0].to_le_bytes());
            output[52..56].copy_from_slice(&layout.sequences[1].to_le_bytes());
        }
        Err(error) => output[4] = error as u8,
    }
    RESPONSE_SIZE
}

#[cfg(all(
    any(
        feature = "security-epoch-preview",
        feature = "security-epoch-maintenance"
    ),
    feature = "mcu-esp32s2",
    not(test)
))]
pub fn handle(
    request: &[u8],
    descriptor_address: u32,
    phase: Phase,
    output: &mut [u8; 64],
) -> Option<usize> {
    use crate::platform::{ota, usb_update};

    if request.first() != Some(&REQUEST) {
        return None;
    }
    let slot = match requested_slot(request, phase) {
        Ok(slot) => slot,
        Err(error) => return Some(encode(u8::MAX, Err(error), output)),
    };
    let result = (|| {
        let before = ota::qualified_layout(descriptor_address).map_err(|_| PreviewError::Layout)?;
        let image = crate::usb_update::verify_installed_slot(
            &mut usb_update::Esp32S2UpdateBackend::new(descriptor_address),
            slot,
            &usb_update::trusted_update_key_digest(),
        )
        .map_err(|_| PreviewError::Image)?;
        let after = ota::qualified_layout(descriptor_address).map_err(|_| PreviewError::Layout)?;
        if before != after {
            return Err(PreviewError::Layout);
        }
        Ok((after, image))
    })();
    Some(encode(slot, result, output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_requires_an_exact_slot_request_and_an_idle_updater() {
        for slot in 0..2 {
            assert_eq!(requested_slot(&[REQUEST, slot], Phase::Idle), Ok(slot));
            for phase in [
                Phase::Erasing,
                Phase::Receiving,
                Phase::Verifying,
                Phase::Activated,
                Phase::Failed,
            ] {
                assert_eq!(
                    requested_slot(&[REQUEST, slot], phase),
                    Err(PreviewError::Busy)
                );
            }
        }
        for request in [
            &[][..],
            &[REQUEST],
            &[REQUEST, 2],
            &[REQUEST, 0, 0],
            &[0, 0],
        ] {
            assert_eq!(
                requested_slot(request, Phase::Idle),
                Err(PreviewError::Request)
            );
        }
    }

    #[test]
    fn error_responses_never_retain_previous_image_information() {
        let mut output = [0xa5; 64];
        assert_eq!(encode(1, Err(PreviewError::Image), &mut output), 64);
        assert_eq!(&output[..6], &[b'R', b'K', b'E', b'1', 3, 1]);
        assert!(output[6..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn successful_preview_contains_only_the_documented_fields() {
        let layout = QualifiedLayout {
            running_slot: 1,
            sequences: [3, 4],
        };
        let image = VerifiedInstalledImage {
            secure_version: 4,
            signed_image_bytes: 417792,
            signed_content_digest: [0x5a; 32],
        };
        let mut output = [0xa5; 64];
        assert_eq!(encode(0, Ok((layout, image)), &mut output), 64);
        assert_eq!(&output[..8], b"RKE1\0\0\x01\0");
        assert_eq!(u32::from_le_bytes(output[8..12].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_le_bytes(output[12..16].try_into().unwrap()),
            417792
        );
        assert_eq!(&output[16..48], &[0x5a; 32]);
        assert_eq!(u32::from_le_bytes(output[48..52].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(output[52..56].try_into().unwrap()), 4);
        assert_eq!(&output[56..], &[0; 8]);
    }
}
