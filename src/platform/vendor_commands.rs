//! Vendor request dispatch. Startup keeps ownership of storage, USB and FIDO resources.

use crate::usb_update::StatusCode;

trait Handlers {
    fn diagnostics(&mut self, request: &[u8], response: &mut [u8; 64]) -> Option<usize>;
    fn security_status(&mut self, response: &mut [u8; 64]) -> usize;
    fn update(&mut self, request: &[u8], present: bool, response: &mut [u8; 64]) -> usize;
    fn confirm_update(&mut self) -> bool;
}

fn first_diagnostic_response(
    response: &mut [u8; 64],
    maintenance: impl FnOnce(&mut [u8; 64]) -> Option<usize>,
    preview: impl FnOnce(&mut [u8; 64]) -> Option<usize>,
    memory: impl FnOnce(&mut [u8; 64]) -> Option<usize>,
) -> Option<usize> {
    maintenance(response)
        .or_else(|| preview(response))
        .or_else(|| memory(response))
}

fn dispatch(handlers: &mut impl Handlers, request: &[u8], response: &mut [u8; 64]) -> usize {
    let mut length = if let Some(length) = handlers.diagnostics(request, response) {
        length
    } else if request == [super::security_status::REQUEST] {
        handlers.security_status(response)
    } else {
        handlers.update(request, false, response)
    };
    if response[0] == StatusCode::UserPresenceRequired as u8 && handlers.confirm_update() {
        length = handlers.update(request, true, response);
    }
    length
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
use super::s2_user_presence::{self, UserPresenceWaitHook, WemosS2MiniUserHardware};
#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
use crate::usb_update::{UpdateBackend, UsbUpdater};
#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
use core::cell::RefCell;

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
struct S2Handlers<'a, B: UpdateBackend> {
    updater: &'a mut UsbUpdater<B>,
    #[cfg(any(
        feature = "security-epoch-preview",
        feature = "security-epoch-maintenance"
    ))]
    descriptor_address: u32,
    secure_version: u32,
    hardware: &'a RefCell<WemosS2MiniUserHardware>,
    wait_hook: &'a dyn UserPresenceWaitHook,
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
impl<B: UpdateBackend> Handlers for S2Handlers<'_, B> {
    fn diagnostics(&mut self, request: &[u8], response: &mut [u8; 64]) -> Option<usize> {
        #[cfg(not(feature = "release-flash-encryption"))]
        let _ = (&request, &response);
        first_diagnostic_response(
            response,
            |_response| {
                #[cfg(feature = "security-epoch-maintenance")]
                {
                    super::security_epoch_maintenance::handle(
                        request,
                        self.descriptor_address,
                        self.updater.phase(),
                        self.hardware,
                        self.wait_hook,
                        _response,
                    )
                }
                #[cfg(not(feature = "security-epoch-maintenance"))]
                {
                    None
                }
            },
            |_response| {
                #[cfg(any(
                    feature = "security-epoch-preview",
                    feature = "security-epoch-maintenance"
                ))]
                {
                    super::security_epoch_preview::handle(
                        request,
                        self.descriptor_address,
                        self.updater.phase(),
                        _response,
                    )
                }
                #[cfg(not(any(
                    feature = "security-epoch-preview",
                    feature = "security-epoch-maintenance"
                )))]
                {
                    None
                }
            },
            |_response| {
                #[cfg(feature = "release-flash-encryption")]
                {
                    (*request == [super::memory_protection::REQUEST])
                        .then(|| super::memory_protection::status(_response))
                }
                #[cfg(not(feature = "release-flash-encryption"))]
                {
                    None
                }
            },
        )
    }

    fn security_status(&mut self, response: &mut [u8; 64]) -> usize {
        super::security_status::read(self.secure_version).encode(response)
    }

    fn update(&mut self, request: &[u8], present: bool, response: &mut [u8; 64]) -> usize {
        self.updater.handle(request, present, response)
    }

    fn confirm_update(&mut self) -> bool {
        s2_user_presence::confirm_update_user_presence(self.hardware, self.wait_hook)
    }
}

#[cfg(all(feature = "usb-signed-update", feature = "mcu-esp32s2", not(test)))]
pub fn handle<B: UpdateBackend>(
    request: &[u8],
    updater: &mut UsbUpdater<B>,
    _descriptor_address: u32,
    secure_version: u32,
    hardware: &RefCell<WemosS2MiniUserHardware>,
    wait_hook: &dyn UserPresenceWaitHook,
    response: &mut [u8; 64],
) -> usize {
    dispatch(
        &mut S2Handlers {
            updater,
            #[cfg(any(
                feature = "security-epoch-preview",
                feature = "security-epoch-maintenance"
            ))]
            descriptor_address: _descriptor_address,
            secure_version,
            hardware,
            wait_hook,
        },
        request,
        response,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

    #[derive(Default)]
    struct FakeHandlers {
        calls: Vec<(&'static str, Vec<u8>)>,
        diagnostic: bool,
        status: u8,
        approved: bool,
    }

    impl Handlers for FakeHandlers {
        fn diagnostics(&mut self, request: &[u8], response: &mut [u8; 64]) -> Option<usize> {
            self.calls.push(("diagnostic", request.to_vec()));
            if !self.diagnostic {
                return None;
            }
            response[..4].copy_from_slice(b"RKM1");
            Some(64)
        }
        fn security_status(&mut self, response: &mut [u8; 64]) -> usize {
            self.calls.push(("security", vec![]));
            response[..4].copy_from_slice(b"RKS1");
            32
        }
        fn update(&mut self, request: &[u8], present: bool, response: &mut [u8; 64]) -> usize {
            self.calls.push((
                if present { "approved" } else { "update" },
                request.to_vec(),
            ));
            response[0] = if present {
                StatusCode::Ok as u8
            } else {
                self.status
            };
            if present { 12 } else { 8 }
        }
        fn confirm_update(&mut self) -> bool {
            self.calls.push(("presence", vec![]));
            self.approved
        }
    }

    #[test]
    fn diagnostic_selection_stops_after_maintenance_preview_or_memory_reply() {
        let names = ["maintenance", "preview", "memory"];
        let magic = [b"RKM1", b"RKE1", b"RKMP"];
        for (lengths, selected) in [
            ([Some(17), Some(23), Some(64)], Some(0)),
            ([None, Some(23), Some(64)], Some(1)),
            ([None, None, Some(64)], Some(2)),
            ([None, None, None], None),
        ] {
            let calls = core::cell::RefCell::new(Vec::new());
            let handler = |index: usize, response: &mut [u8; 64]| {
                calls.borrow_mut().push(names[index]);
                lengths[index].inspect(|_| response[..4].copy_from_slice(magic[index]))
            };
            let mut response = [0xa5; 64];
            let length = first_diagnostic_response(
                &mut response,
                |response| handler(0, response),
                |response| handler(1, response),
                |response| handler(2, response),
            );
            assert_eq!(length, selected.and_then(|index| lengths[index]));
            assert_eq!(calls.into_inner(), names[..selected.unwrap_or(2) + 1]);
            if let Some(index) = selected {
                assert_eq!(&response[..4], magic[index]);
            } else {
                assert_eq!(response, [0xa5; 64]);
            }
        }
    }

    #[test]
    fn memory_status_has_a_distinct_code_and_cannot_satisfy_a_maintenance_plan() {
        let memory_request = super::super::memory_protection::REQUEST;
        assert_eq!(memory_request, 0x16);
        assert!(
            ![
                super::super::security_status::REQUEST,
                super::super::security_epoch_preview::REQUEST,
                0x13,
                0x14,
                0x15,
            ]
            .contains(&memory_request)
        );

        let plan_digest = [7; 32];
        for request in [&[memory_request][..], &[0x14][..]] {
            assert_eq!(
                super::super::security_epoch_plan::requested_images(request, &plan_digest),
                None
            );
        }
        let mut request = [7; 97];
        request[0] = 0x14;
        assert_eq!(
            super::super::security_epoch_plan::requested_images(&request, &plan_digest),
            Some(Some([[7; 32]; 2]))
        );
        request[0] = memory_request;
        assert_eq!(
            super::super::security_epoch_plan::requested_images(&request, &plan_digest),
            None
        );
    }

    #[test]
    fn diagnostic_reply_never_falls_through_to_update_or_security() {
        let request = [super::super::security_status::REQUEST];
        let mut handlers = FakeHandlers {
            diagnostic: true,
            ..Default::default()
        };
        let mut response = [0; 64];
        assert_eq!(dispatch(&mut handlers, &request, &mut response), 64);
        assert_eq!(&response[..4], b"RKM1");
        assert_eq!(handlers.calls, [("diagnostic", request.to_vec())]);
    }

    #[test]
    fn security_status_requires_exact_request_and_preserves_reply() {
        for request in [vec![], vec![0x11], vec![0x11, 0], vec![0xff]] {
            let mut handlers = FakeHandlers::default();
            let mut response = [0; 64];
            let length = dispatch(&mut handlers, &request, &mut response);
            if request == [0x11] {
                assert_eq!(length, 32);
                assert_eq!(&response[..4], b"RKS1");
                assert_eq!(
                    handlers.calls,
                    [("diagnostic", request), ("security", vec![])]
                );
            } else {
                assert_eq!(length, 8);
                assert_eq!(
                    handlers.calls,
                    [("diagnostic", request.clone()), ("update", request)]
                );
            }
        }
    }

    #[test]
    fn only_presence_required_can_request_approval_and_retry_the_same_payload() {
        let request = [1, 0xab, 0xcd];
        for status in 0..=u8::MAX {
            for approved in [false, true] {
                let mut handlers = FakeHandlers {
                    status,
                    approved,
                    ..Default::default()
                };
                let mut response = [0; 64];
                let length = dispatch(&mut handlers, &request, &mut response);
                let mut expected = vec![
                    ("diagnostic", request.to_vec()),
                    ("update", request.to_vec()),
                ];
                let needs_presence = status == StatusCode::UserPresenceRequired as u8;
                if needs_presence {
                    expected.push(("presence", vec![]));
                }
                if needs_presence && approved {
                    expected.push(("approved", request.to_vec()));
                }
                assert_eq!(handlers.calls, expected);
                assert_eq!(length, if needs_presence && approved { 12 } else { 8 });
                assert_eq!(
                    response[0],
                    if needs_presence && approved {
                        0
                    } else {
                        status
                    }
                );
            }
        }
    }
}
