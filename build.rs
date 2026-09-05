#[path = "src/usb_identity.rs"]
mod usb_identity;

fn main() {
    verify_partition_contract();
    require_update_key_digest();
    require_provisioning_acknowledgement();
    require_attestation_import_acknowledgement();
    require_physical_fault_test_acknowledgement();
    verify_usb_identity();
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("xtensa") {
        linker_be_nice();

        if std::env::var_os("CARGO_FEATURE_RELEASE_FLASH_ENCRYPTION").is_some() {
            println!("cargo:rustc-link-search=ld");
            println!("cargo:rustc-link-arg=-Tesp32s2-encrypted-store.x");
        }

        // linkall.x must be the last linker script.
        println!("cargo:rustc-link-arg=-Tlinkall.x");
    }
}

fn require_update_key_digest() {
    const NAME: &str = "RISSO_KEY_UPDATE_KEY_DIGEST_HEX";
    println!("cargo:rerun-if-env-changed={NAME}");
    if std::env::var_os("CARGO_FEATURE_USB_SIGNED_UPDATE").is_none() {
        return;
    }
    let digest = std::env::var(NAME).unwrap_or_else(|_| panic!("{NAME} is required"));
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{NAME} must contain exactly 64 lowercase hexadecimal characters"
    );
    println!("cargo:rustc-env={NAME}={digest}");
}

fn require_attestation_import_acknowledgement() {
    println!("cargo:rerun-if-env-changed=RISSO_KEY_ATTESTATION_IMPORT_ACK");
    if std::env::var_os("CARGO_FEATURE_ATTESTATION_IMPORT").is_none() {
        return;
    }
    assert_eq!(
        std::env::var("RISSO_KEY_ATTESTATION_IMPORT_ACK").as_deref(),
        Ok("INSTALL_ATTESTATION"),
        "attestation-import requires explicit INSTALL_ATTESTATION acknowledgement"
    );
    for incompatible in [
        "STORAGE_PROVISIONING",
        "PHYSICAL_STORAGE_FAULT_TEST",
        "USB_SIGNED_UPDATE",
    ] {
        assert!(
            std::env::var_os(format!("CARGO_FEATURE_{incompatible}")).is_none(),
            "attestation import must remain a separate build"
        );
    }
}

fn require_physical_fault_test_acknowledgement() {
    const ACKNOWLEDGEMENT: &str = "INTERRUPT_FIDO_STORE";
    println!("cargo:rerun-if-env-changed=RISSO_KEY_PHYSICAL_FAULT_TEST_ACK");
    if std::env::var_os("CARGO_FEATURE_PHYSICAL_STORAGE_FAULT_TEST").is_none() {
        return;
    }

    assert_eq!(
        std::env::var("RISSO_KEY_PHYSICAL_FAULT_TEST_ACK").as_deref(),
        Ok(ACKNOWLEDGEMENT),
        "physical-storage-fault-test requires RISSO_KEY_PHYSICAL_FAULT_TEST_ACK={ACKNOWLEDGEMENT}"
    );
    assert!(
        std::env::var_os("CARGO_FEATURE_STORAGE_PROVISIONING").is_none(),
        "physical fault injection and storage provisioning must remain separate builds"
    );
}

fn verify_usb_identity() {
    for variable in [
        "RISSO_KEY_USB_VID",
        "RISSO_KEY_USB_PID",
        "RISSO_KEY_USB_SERIAL",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if std::env::var_os("CARGO_FEATURE_USB_BRINGUP").is_none() {
        return;
    }

    let vid = std::env::var("RISSO_KEY_USB_VID").expect("RISSO_KEY_USB_VID is required");
    let pid = std::env::var("RISSO_KEY_USB_PID").expect("RISSO_KEY_USB_PID is required");
    let serial = std::env::var("RISSO_KEY_USB_SERIAL").expect("RISSO_KEY_USB_SERIAL is required");
    usb_identity::UsbIdentity::from_build_values(&vid, &pid, &serial)
        .expect("invalid USB identity build values");
}

fn require_provisioning_acknowledgement() {
    const ACKNOWLEDGEMENT: &str = "ERASE_FIDO_STORE";
    println!("cargo:rerun-if-env-changed=RISSO_KEY_PROVISIONING_ACK");
    if std::env::var_os("CARGO_FEATURE_STORAGE_PROVISIONING").is_none() {
        return;
    }

    assert_eq!(
        std::env::var("RISSO_KEY_PROVISIONING_ACK").as_deref(),
        Ok(ACKNOWLEDGEMENT),
        "storage-provisioning requires RISSO_KEY_PROVISIONING_ACK={ACKNOWLEDGEMENT}"
    );
}

fn verify_partition_contract() {
    const LEGACY_NVS: [&str; 5] = ["nvs", "data", "nvs", "0x9000", "0x6000"];
    const LEGACY_PHY: [&str; 5] = ["phy_init", "data", "phy", "0xf000", "0x1000"];
    const LEGACY_FACTORY: [&str; 5] = ["factory", "app", "factory", "0x10000", "0x3d0000"];
    const MIGRATION_FACTORY: [&str; 5] = ["factory", "app", "factory", "0x10000", "0x3c0000"];
    const MIGRATION_NVS: [&str; 5] = ["nvs", "data", "nvs", "0x3d0000", "0x6000"];
    const MIGRATION_PHY: [&str; 5] = ["phy_init", "data", "phy", "0x3d6000", "0x1000"];
    const AB_OTADATA: [&str; 5] = ["otadata", "data", "ota", "0x0f000", "0x002000"];
    const AB_NVS: [&str; 5] = ["nvs", "data", "nvs", "0x11000", "0x006000"];
    const AB_PHY: [&str; 5] = ["phy_init", "data", "phy", "0x17000", "0x001000"];
    const AB_OTA0: [&str; 5] = ["ota_0", "app", "ota_0", "0x20000", "0x1e0000"];
    const AB_OTA1: [&str; 5] = ["ota_1", "app", "ota_1", "0x200000", "0x1e0000"];
    const EXPECTED_STORE: [&str; 5] = ["fido_store", "data", "littlefs", "0x3e0000", "0x20000"];
    const ENCRYPTED_AB_OTADATA: [&str; 6] =
        ["otadata", "data", "ota", "0x0f000", "0x002000", "encrypted"];
    const ENCRYPTED_AB_NVS: [&str; 6] = ["nvs", "data", "nvs", "0x11000", "0x006000", ""];
    const ENCRYPTED_AB_PHY: [&str; 6] = ["phy_init", "data", "phy", "0x17000", "0x001000", ""];
    const ENCRYPTED_AB_OTA0: [&str; 6] =
        ["ota_0", "app", "ota_0", "0x20000", "0x1e0000", "encrypted"];
    const ENCRYPTED_AB_OTA1: [&str; 6] =
        ["ota_1", "app", "ota_1", "0x200000", "0x1e0000", "encrypted"];
    const ENCRYPTED_STORE: [&str; 6] = [
        "fido_store",
        "data",
        "littlefs",
        "0x3e0000",
        "0x20000",
        "encrypted",
    ];

    println!("cargo:rerun-if-env-changed=RISSO_KEY_PARTITION_PROFILE");
    println!("cargo:rerun-if-changed=partitions.csv");
    println!("cargo:rerun-if-changed=partitions-e000.csv");
    println!("cargo:rerun-if-changed=partitions-ab.csv");
    println!("cargo:rerun-if-changed=partitions-ab-encrypted.csv");
    println!("cargo:rerun-if-changed=ld/esp32s2-encrypted-store.x");
    let profile =
        std::env::var("RISSO_KEY_PARTITION_PROFILE").unwrap_or_else(|_| "legacy-0x8000".to_owned());
    let encrypted_feature = std::env::var_os("CARGO_FEATURE_RELEASE_FLASH_ENCRYPTION").is_some();
    let path = match profile.as_str() {
        "legacy-0x8000" => "partitions.csv",
        "e000-migration" => "partitions-e000.csv",
        "signed-ab" => "partitions-ab.csv",
        "signed-ab-encrypted" => "partitions-ab-encrypted.csv",
        _ => panic!(
            "RISSO_KEY_PARTITION_PROFILE must be legacy-0x8000, e000-migration, signed-ab, or signed-ab-encrypted"
        ),
    };
    assert_eq!(
        encrypted_feature,
        profile == "signed-ab-encrypted",
        "release-flash-encryption and the signed-ab-encrypted partition profile must be selected together"
    );
    if encrypted_feature {
        assert_eq!(
            std::env::var("PROFILE").as_deref(),
            Ok("release"),
            "release-flash-encryption requires a Cargo release build"
        );
    }
    let table = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("{path} must exist and be valid UTF-8"));
    let rows = table
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split(',').map(str::trim).collect::<Vec<_>>())
        .collect::<Vec<_>>();

    let matches = match profile.as_str() {
        "legacy-0x8000" => verify_rows(
            &rows,
            &[LEGACY_NVS, LEGACY_PHY, LEGACY_FACTORY, EXPECTED_STORE],
        ),
        "e000-migration" => verify_rows(
            &rows,
            &[
                MIGRATION_FACTORY,
                MIGRATION_NVS,
                MIGRATION_PHY,
                EXPECTED_STORE,
            ],
        ),
        "signed-ab" => verify_rows(
            &rows,
            &[AB_OTADATA, AB_NVS, AB_PHY, AB_OTA0, AB_OTA1, EXPECTED_STORE],
        ),
        "signed-ab-encrypted" => verify_rows(
            &rows,
            &[
                ENCRYPTED_AB_OTADATA,
                ENCRYPTED_AB_NVS,
                ENCRYPTED_AB_PHY,
                ENCRYPTED_AB_OTA0,
                ENCRYPTED_AB_OTA1,
                ENCRYPTED_STORE,
            ],
        ),
        _ => unreachable!(),
    };
    assert!(
        matches,
        "{path} does not match the fixed {profile} partition contract"
    );
}

fn verify_rows<const N: usize>(rows: &[Vec<&str>], expected: &[[&str; N]]) -> bool {
    rows.len() == expected.len()
        && rows
            .iter()
            .zip(expected.iter())
            .all(|(row, expected_row)| row.starts_with(expected_row))
}

fn linker_be_nice() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let kind = &args[1];
        let what = &args[2];

        match kind.as_str() {
            "undefined-symbol" => match what.as_str() {
                what if what.starts_with("_defmt_") => {
                    eprintln!("\n`defmt` is missing. Add `defmt.x` as a linker script.\n");
                }
                "_stack_start" => {
                    eprintln!("\nThe `linkall.x` linker script is missing.\n");
                }
                "free"
                | "malloc"
                | "calloc"
                | "get_free_internal_heap_size"
                | "malloc_internal"
                | "realloc_internal"
                | "calloc_internal"
                | "free_internal" => {
                    eprintln!("\nThe allocator is missing. Check the `esp-alloc` setup.\n");
                }
                _ => (),
            },
            _ => std::process::exit(1),
        }

        std::process::exit(0);
    }

    println!(
        "cargo:rustc-link-arg=-Wl,--error-handling-script={}",
        std::env::current_exe().unwrap().display()
    );
}
