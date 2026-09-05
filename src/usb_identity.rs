//! Build-time and runtime policy for the host-visible USB identity.

pub const MAX_USB_SERIAL_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    EmptySerial,
    InvalidNumber,
    InvalidSerial,
    ReservedProductId,
    ReservedVendorId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbIdentity<'a> {
    pub vid: u16,
    pub pid: u16,
    pub serial: &'a str,
}

impl<'a> UsbIdentity<'a> {
    pub fn new(vid: u16, pid: u16, serial: &'a str) -> Result<Self, IdentityError> {
        if vid == 0 || vid == u16::MAX {
            return Err(IdentityError::ReservedVendorId);
        }
        if pid == 0 || pid == u16::MAX {
            return Err(IdentityError::ReservedProductId);
        }
        if serial.is_empty() {
            return Err(IdentityError::EmptySerial);
        }
        if !is_valid_usb_serial(serial) {
            return Err(IdentityError::InvalidSerial);
        }

        Ok(Self { vid, pid, serial })
    }

    pub fn from_build_values(
        vid: &'a str,
        pid: &'a str,
        serial: &'a str,
    ) -> Result<Self, IdentityError> {
        Self::new(parse_u16(vid)?, parse_u16(pid)?, serial)
    }
}

/// Restricts the host-visible serial to a short, predictable ASCII form.
pub fn is_valid_usb_serial(serial: &str) -> bool {
    !serial.is_empty()
        && serial.len() <= MAX_USB_SERIAL_LENGTH
        && serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_u16(value: &str) -> Result<u16, IdentityError> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));

    u16::from_str_radix(digits, radix).map_err(|_| IdentityError::InvalidNumber)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_identity_values() {
        assert_eq!(
            UsbIdentity::from_build_values("0x1209", "1", "RK-2026_0001.test"),
            Ok(UsbIdentity {
                vid: 0x1209,
                pid: 1,
                serial: "RK-2026_0001.test"
            })
        );
    }

    #[test]
    fn rejects_reserved_or_malformed_numbers() {
        assert_eq!(
            UsbIdentity::new(0, 1, "valid"),
            Err(IdentityError::ReservedVendorId)
        );
        assert_eq!(
            UsbIdentity::new(1, u16::MAX, "valid"),
            Err(IdentityError::ReservedProductId)
        );
        assert_eq!(
            UsbIdentity::from_build_values("invalid", "1", "valid"),
            Err(IdentityError::InvalidNumber)
        );
    }

    #[test]
    fn rejects_empty_long_or_ambiguous_usb_serials() {
        assert_eq!(UsbIdentity::new(1, 1, ""), Err(IdentityError::EmptySerial));
        for serial in ["contains a space", "unicode-ä"] {
            assert_eq!(
                UsbIdentity::new(1, 1, serial),
                Err(IdentityError::InvalidSerial)
            );
        }
        assert_eq!(
            UsbIdentity::new(1, 1, &"x".repeat(MAX_USB_SERIAL_LENGTH + 1)),
            Err(IdentityError::InvalidSerial)
        );
    }
}
