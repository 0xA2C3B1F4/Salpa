// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

func loginKeychain() throws -> SecKeychain {
    var result: SecKeychain?
    try check(
        SecKeychainOpen(
            fm.homeDirectoryForCurrentUser.appendingPathComponent(
                "Library/Keychains/login.keychain-db"
            ).path, &result))
    return result!
}

func query(_ role: String) throws -> [String: Any] {
    try require(roles.contains(role), "Unknown key role")
    return [
        kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
        kSecAttrAccount as String: role, kSecAttrSynchronizable as String: false,
        kSecMatchSearchList as String: [try loginKeychain()]
    ]
}

func acls(_ access: SecAccess) throws -> [SecACL] {
    var result: CFArray?
    try check(SecAccessCopyACLList(access, &result))
    return result! as! [SecACL]
}

func verifyPolicy(_ role: String) throws {
    var q = try query(role)
    q[kSecReturnRef as String] = true
    var ref: CFTypeRef?
    try check(SecItemCopyMatching(q as CFDictionary, &ref))
    var access: SecAccess?
    try check(SecKeychainItemCopyAccess(ref as! SecKeychainItem, &access))
    var decrypt = false
    var owner = false
    for acl in try acls(access!) {
        var apps: CFArray?
        var desc: CFString?
        var flags: SecKeychainPromptSelector = []
        try check(SecACLCopyContents(acl, &apps, &desc, &flags))
        let auths = SecACLCopyAuthorizations(acl) as! [String]
        // The file Keychain adds integrity and partition bookkeeping entries.
        if auths == [kSecACLAuthorizationIntegrity as String]
            || auths == [kSecACLAuthorizationPartitionID as String]
        {
            continue
        }
        // macOS 26 returns the stored 16-bit selector byte-swapped (0x0100).
        // Do not rely on this bit for owner authentication: LA below is mandatory,
        // and an actual no-UI retrieval must also fail before every access.
        try require(
            apps != nil && CFArrayGetCount(apps!) == 0
                && [UInt16(1), UInt16(256)].contains(flags.rawValue),
            """
            Keychain ACL changed: trusted applications or password bypass are \
            forbidden. Do not select Always Allow.
            """
        )
        decrypt = decrypt || auths.contains(kSecACLAuthorizationDecrypt as String)
        owner = owner || auths.contains(kSecACLAuthorizationChangeACL as String)
    }
    try require(decrypt && owner, "Incomplete Keychain access policy")
}

func noUI(_ role: String) throws {
    try verifyPolicy(role)
    try check(SecKeychainSetUserInteractionAllowed(false))
    defer {
        SecKeychainSetUserInteractionAllowed(true)
    }
    var q = try query(role)
    q[kSecReturnData as String] = true
    var result: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &result)
    try require(
        status == errSecInteractionNotAllowed || status == errSecAuthFailed,
        "Keychain did not enforce authentication; operation refused")
    try require(result == nil, "Keychain unexpectedly returned data without authentication")
}


func loadKey(_ role: String, reason: String? = nil) throws -> Data {
    try noUI(role)
    try authenticate(
        reason
            ?? (role == "signing"
                ? "approve use of the existing Salpa firmware signing key"
                : role == attestationRole
                    ? "approve use of the ESP32-S2 development FIDO attestation"
                    : "approve Salpa device flash encryption"))
    var q = try query(role)
    q[kSecReturnData as String] = true
    var result: CFTypeRef?
    try check(SecItemCopyMatching(q as CFDictionary, &result))
    try verifyPolicy(role)  // Reject Always Allow changes before using the key.
    guard let data = result as? Data else {
        throw Failure(message: "Keychain returned no key")
    }
    return data
}


func importKey(_ role: String, _ path: String) throws {
    var data = try readFile(path, secret: true, max: 16384)
    defer {
        data.resetBytes(in: 0..<data.count)
    }
    try importData(role, data, reference: path)
}

func importData(_ role: String, _ data: Data, reference path: String) throws {
    try require(roles.contains(role), "Unknown key role")
    if role == "signing" {
        _ = try rsa(data)
    } else if role == attestationRole {
        _ = try validateAttestationPayload(data)
    } else {
        try require(data.count == 32, "Flash key must be exactly 32 bytes")
    }
    var access: SecAccess?
    try check(SecAccessCreate(labels[role]! as CFString, [] as CFArray, &access))
    for acl in try acls(access!) {
        try check(
            SecACLSetContents(
                acl, [] as CFArray, labels[role]! as CFString,
                SecKeychainPromptSelector(rawValue: 1)))
    }
    var q = try query(role)
    q.removeValue(forKey: kSecMatchSearchList as String)
    q[kSecUseKeychain as String] = try loginKeychain()
    q[kSecAttrAccess as String] = access!
    q[kSecAttrLabel as String] = labels[role]!
    q[kSecValueData as String] = data
    let added = SecItemAdd(q as CFDictionary, nil)  // Never overwrite an existing item.
    if added == errSecDuplicateItem {
        var existing = try loadKey(role)
        defer {
            existing.resetBytes(in: 0..<existing.count)
        }
        try require(existing == data, "Existing Keychain item differs; replacement is forbidden")
    } else {
        try check(added)
        try noUI(role)
    }
    try verifyPolicy(role)
    if role == attestationRole {
        let identity = try validateAttestationPayload(data)
        // A new account preserves the historical missing-original 'attestation' entry.
        try registry(
            role,
            [
                "name": labels[role]!,
                "purpose": "New development FIDO attestation for the ESP32-S2",
                "device_or_group": "ESP32-S2 development attestation identity",
                "responsible_person": NSUserName(),
                "keychain_reference": [
                    "path": "~/Library/Keychains/login.keychain-db", "service": service,
                    "account": role, "synchronizable": false
                ],
                "access":
                    """
                current macOS user; no trusted applications; fresh macOS owner \
                authentication plus Keychain access confirmation for every operation
                """,
                "original_copy": path, "certificate_sha256": identity.certificateSHA256,
                "public_key_x963_sha256": identity.publicKeyX963SHA256,
                "status":
                    """
                imported; encrypted backup and separate-process restore test required \
                before staging
                """,
                "imported_at": now(),
                "retention":
                    """
                Retain durable original files and encrypted backup; deletion requires \
                explicit separate authorization
                """
            ], preserveExisting: true)
        try requireAttestationInventory(identity, record: attestationRecord())
        return
    }
    try registry(
        role,
        [
            "name": labels[role]!,
            "purpose": role == "signing"
                ? "ESP32-S2 Secure Boot V2 and signed firmware updates"
                : "ESP32-S2 device-specific AES-128-XTS flash encryption and recovery",
            "device_or_group": role == "signing"
                ? "firmware signing trust root" : "ESP32-S2 device",
            "responsible_person": NSUserName(),
            "keychain_reference": [
                "path": "~/Library/Keychains/login.keychain-db", "service": service,
                "account": role, "synchronizable": false
            ],
            "access":
                """
            current macOS user; no trusted applications; fresh macOS owner \
            authentication plus Keychain access confirmation for every operation
            """,
            "original_copy": path,
            "status": "imported; interactive use and backup not yet verified",
            "backup_location_reference": NSNull(), "restore_test_at": NSNull(),
            "imported_at": now(),
            "retention": role == "signing"
                ? "Keep original until integration and offline restore verified"
                : """
                Keep through physical acceptance and encrypted recovery; deletion \
                requires separate final ROM-lockdown decision
                """,
            "public_key_pkcs1_sha256": role == "signing" ? try publicHash(data) : "not applicable"
        ], preserveExisting: true)
}
