//! Host-only build input compatibility; never linked into firmware.

use std::prelude::v1::*;

// Environment names are command-line interfaces; retain the previous aliases.
pub fn build_var_os(name: &str) -> Option<std::ffi::OsString> {
    let legacy = name.replacen("SALPA_", "RISSO_KEY_", 1);
    let current = std::env::var_os(name);
    let previous = std::env::var_os(&legacy);
    resolve(current, previous)
        .unwrap_or_else(|_| panic!("conflicting environment variables: {name} and {legacy}"))
}

pub fn build_var(name: &str) -> Result<String, std::env::VarError> {
    match build_var_os(name) {
        Some(value) => value.into_string().map_err(std::env::VarError::NotUnicode),
        None => Err(std::env::VarError::NotPresent),
    }
}

pub fn configure_build_environment() {
    for name in [
        "SALPA_ATTESTATION_CERT_SHA256_FILE",
        "SALPA_ATTESTATION_IMPORT_ACK",
        "SALPA_ATTESTATION_PUBLIC_FILE",
        "SALPA_DEV_ATTESTATION_CERT",
        "SALPA_DEV_ATTESTATION_KEY",
        "SALPA_EPOCH_MAINTENANCE_ACK",
        "SALPA_EPOCH_PLAN_PATH",
        "SALPA_EPOCH_PREVIEW_ACK",
        "SALPA_PARTITION_PROFILE",
        "SALPA_PHYSICAL_FAULT_TEST_ACK",
        "SALPA_PROVISIONING_ACK",
        "SALPA_UPDATE_KEY_DIGEST_HEX",
        "SALPA_USB_PID",
        "SALPA_USB_SERIAL",
        "SALPA_USB_VID",
    ] {
        let legacy = name.replacen("SALPA_", "RISSO_KEY_", 1);
        std::println!("cargo:rerun-if-env-changed={name}");
        std::println!("cargo:rerun-if-env-changed={legacy}");
        if let Some(value) = build_var_os(name) {
            let value = value.to_str().expect("build environment must be UTF-8");
            assert!(
                !value.contains(['\r', '\n']),
                "invalid line break in {name}"
            );
            std::println!("cargo:rustc-env={name}={value}");
        }
    }
}

fn resolve(
    current: Option<std::ffi::OsString>,
    previous: Option<std::ffi::OsString>,
) -> Result<Option<std::ffi::OsString>, ()> {
    if let (Some(a), Some(b)) = (&current, &previous)
        && a != b
    {
        return Err(());
    }
    Ok(current.or(previous))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn either_name_and_equal_aliases_resolve_identically() {
        let value = Some(OsString::from("fixture-value"));
        assert_eq!(resolve(value.clone(), None), Ok(value.clone()));
        assert_eq!(resolve(None, value.clone()), Ok(value.clone()));
        assert_eq!(resolve(value.clone(), value.clone()), Ok(value));
        assert_eq!(resolve(None, None), Ok(None));
    }

    #[test]
    fn conflicting_or_empty_aliases_do_not_select_an_arbitrary_value() {
        assert_eq!(
            resolve(Some("first".into()), Some("second".into())),
            Err(())
        );
        assert_eq!(resolve(Some("".into()), Some("second".into())), Err(()));
    }
}
