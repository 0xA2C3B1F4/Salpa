//! Complete application replies at the firmware/USB boundary.
//!
//! Dispatch success, CTAP status, and transport acceptance are separate facts.
//! This module consumes them before clearing the application's response buffer.

use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyError {
    NoPendingRequest,
    ResponseTooLong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyDisposition {
    Queued,
    Discarded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CborCompletion {
    /// A CTAP success reply was accepted by the transport. This is the minimum
    /// boot health check; it does not prove credential persistence or delivery.
    Succeeded,
    Failed,
    Interrupted,
}

fn disposition(result: Result<(), ReplyError>) -> Result<ReplyDisposition, ReplyError> {
    match result {
        Ok(()) => Ok(ReplyDisposition::Queued),
        Err(ReplyError::NoPendingRequest) => Ok(ReplyDisposition::Discarded),
        Err(error) => Err(error),
    }
}

/// Return success only for an accepted CTAP2 success response. Dispatch errors
/// and missing responses produce CTAP Other; resynchronized requests produce
/// no stale reply and cannot confirm a firmware candidate.
pub fn complete_cbor(
    dispatch_succeeded: bool,
    response: &mut [u8],
    reply: impl FnOnce(&[u8]) -> Result<(), ReplyError>,
) -> Result<CborCompletion, ReplyError> {
    let ctap_succeeded = dispatch_succeeded && response.first() == Some(&0x00);
    let result = if dispatch_succeeded && !response.is_empty() {
        reply(response)
    } else {
        reply(&[0x7f])
    };
    response.zeroize();
    match disposition(result)? {
        ReplyDisposition::Queued if ctap_succeeded => Ok(CborCompletion::Succeeded),
        ReplyDisposition::Queued => Ok(CborCompletion::Failed),
        ReplyDisposition::Discarded => Ok(CborCompletion::Interrupted),
    }
}

/// A discarded update request is a normal interruption. Clear the response on
/// both successful and failed completion, just as for CBOR replies.
pub fn complete_update(
    response: &mut [u8],
    reply: impl FnOnce(&[u8]) -> Result<(), ReplyError>,
) -> Result<ReplyDisposition, ReplyError> {
    let result = reply(response);
    response.zeroize();
    disposition(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctap_status_controls_confirmation_even_when_dispatch_succeeds() {
        for status in 0..=u8::MAX {
            let mut response = [status, 0xa0];
            let outcome = complete_cbor(true, &mut response, |bytes| {
                assert_eq!(bytes, [status, 0xa0]);
                Ok(())
            });
            assert_eq!(
                outcome,
                Ok(if status == 0 {
                    CborCompletion::Succeeded
                } else {
                    CborCompletion::Failed
                })
            );
            assert_eq!(response, [0; 2]);
        }
    }

    #[test]
    fn dispatch_failure_or_missing_response_sends_ctap_other() {
        let mut stale_response = [0, 0xa0];
        assert_eq!(
            complete_cbor(false, &mut stale_response, |bytes| {
                assert_eq!(bytes, [0x7f]);
                Ok(())
            }),
            Ok(CborCompletion::Failed)
        );
        assert_eq!(stale_response, [0; 2]);
        assert_eq!(
            complete_cbor(true, &mut [], |bytes| {
                assert_eq!(bytes, [0x7f]);
                Ok(())
            }),
            Ok(CborCompletion::Failed)
        );
    }

    #[test]
    fn transport_abort_and_error_never_confirm_and_always_clear_the_response() {
        for error in [ReplyError::NoPendingRequest, ReplyError::ResponseTooLong] {
            let mut response = [0, 0xa0];
            let outcome = complete_cbor(true, &mut response, |_| Err(error));
            assert_eq!(
                outcome,
                if error == ReplyError::NoPendingRequest {
                    Ok(CborCompletion::Interrupted)
                } else {
                    Err(error)
                }
            );
            assert_eq!(response, [0; 2]);
        }
    }

    #[test]
    fn update_replies_share_abort_handling_and_clear_on_every_result() {
        for result in [
            Ok(()),
            Err(ReplyError::NoPendingRequest),
            Err(ReplyError::ResponseTooLong),
        ] {
            let mut response = [0x5a; 64];
            let outcome = complete_update(&mut response, |bytes| {
                assert_eq!(bytes, [0x5a; 64]);
                result
            });
            assert_eq!(outcome, disposition(result));
            assert_eq!(response, [0; 64]);
        }
    }
}
