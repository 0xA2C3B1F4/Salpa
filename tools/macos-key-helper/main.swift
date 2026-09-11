// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

struct Failure: Error {
    let message: String
}

func require(_ condition: Bool, _ message: String) throws {
    if !condition {
        throw Failure(message: message)
    }
}

func check(_ status: OSStatus) throws {
    try require(status == errSecSuccess, "macOS Security operation failed (\(status))")
}

let fm = FileManager.default
let support = fm.homeDirectoryForCurrentUser.appendingPathComponent(
    "Library/Application Support/RissoKey")
let inventoryURL = support.appendingPathComponent("key-inventory.json")
let service = "fi.rissotek.rissokey.local-keys.v1"
let attestationRole = "attestation-v2"
let roles = ["signing", "flash", attestationRole]
let labels = [
    "signing": "Salpa | Secure Boot V2 signing",
    "flash": "Salpa | ESP32-S2 flash encryption",
    attestationRole: "Salpa | development FIDO attestation"
]
let processSession = UUID().uuidString

func now() -> String {
    ISO8601DateFormatter().string(from: Date())
}

func hash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func privateDirectory(_ url: URL) throws {
    var s = stat()
    if lstat(url.path, &s) == 0 {
        try require(
            (s.st_mode & S_IFMT) == S_IFDIR && s.st_uid == getuid() && s.st_mode & 0o077 == 0,
            "Directory must be owner-only and must not be a symlink")
    } else {
        try fm.createDirectory(
            at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
}

func readFile(_ path: String, secret: Bool = false, max: Int = 16 * 1024 * 1024) throws -> Data {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    try require(fd >= 0, "Cannot open regular input file")
    defer {
        close(fd)
    }
    var s = stat()
    try require(
        fstat(fd, &s) == 0 && (s.st_mode & S_IFMT) == S_IFREG && s.st_size > 0 && s.st_size <= max,
        "Invalid input file")
    if secret {
        try require(
            s.st_uid == getuid() && s.st_mode & 0o077 == 0, "Secret input must be owner-only")
    }
    var data = Data(count: Int(s.st_size))
    let count = data.withUnsafeMutableBytes { read(fd, $0.baseAddress!, $0.count) }
    try require(count == data.count, "Short input read")
    return data
}

func writeNew(_ data: Data, _ path: String) throws {
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try require(fd >= 0, "Output must be a new file in an existing directory")
    var success = false
    defer {
        close(fd)
        if !success {
            unlink(path)
        }
    }
    let count = data.withUnsafeBytes { write(fd, $0.baseAddress!, $0.count) }
    try require(count == data.count && fsync(fd) == 0, "Output write failed")
    success = true
}

func readRegistry() throws -> [String: Any] {
    let object = try JSONSerialization.jsonObject(with: readFile(inventoryURL.path, secret: true))
    guard let root = object as? [String: Any], root["schema"] as? Int == 1,
        root["keys"] is [String: Any]
    else {
        throw Failure(message: "Invalid private key inventory")
    }
    return root
}

func registry(_ role: String, _ changes: [String: Any], preserveExisting: Bool = false) throws {
    try privateDirectory(support)
    var root: [String: Any] = ["schema": 1, "keys": [String: Any]()]
    if fm.fileExists(atPath: inventoryURL.path) {
        root = try readRegistry()
    }
    var keys = root["keys"] as? [String: Any] ?? [:]
    var record = keys[role] as? [String: Any] ?? [:]
    for (key, value) in changes {
        if !preserveExisting || record[key] == nil {
            record[key] = value
        }
    }
    keys[role] = record
    root["keys"] = keys
    let data = try JSONSerialization.data(
        withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
    // Atomic replacement only of our non-secret inventory.
    try data.write(to: inventoryURL, options: .atomic)
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: inventoryURL.path)
}

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

func authenticate(_ reason: String) throws {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer {
        context.invalidate()
    }
    var error: NSError?
    try require(
        context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error),
        "macOS owner authentication is unavailable")
    let semaphore = DispatchSemaphore(value: 0)
    var allowed = false
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
        allowed = success
        semaphore.signal()
    }
    semaphore.wait()
    try require(allowed, "macOS authentication cancelled or failed")
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

func rsa(_ pem: Data) throws -> SecKey {
    guard let text = String(data: pem, encoding: .utf8) else {
        throw Failure(message: "Invalid private PEM")
    }
    let lines = text.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
    guard var der = Data(base64Encoded: lines, options: .ignoreUnknownCharacters) else {
        throw Failure(message: "Invalid PEM encoding")
    }
    // Security expects PKCS#1. Unwrap the PKCS#8 PrivateKeyInfo OCTET STRING.
    if text.contains("BEGIN PRIVATE KEY") {
        func tlv(_ bytes: Data, _ cursor: inout Int) throws -> (UInt8, Data) {
            try require(cursor + 2 <= bytes.count, "Invalid DER")
            let tag = bytes[cursor]
            cursor += 1
            var n = Int(bytes[cursor])
            cursor += 1
            if n & 128 != 0 {
                let count = n & 127
                try require(
                    count > 0 && count <= 4 && cursor + count <= bytes.count, "Invalid DER length")
                n = 0
                for _ in 0..<count {
                    n = n * 256 + Int(bytes[cursor])
                    cursor += 1
                }
            }
            try require(cursor + n <= bytes.count, "Truncated DER")
            let value = Data(bytes[cursor..<cursor + n])
            cursor += n
            return (tag, value)
        }
        var c = 0
        let outer = try tlv(der, &c)
        try require(outer.0 == 0x30 && c == der.count, "Invalid PKCS#8")
        c = 0
        _ = try tlv(outer.1, &c)
        _ = try tlv(outer.1, &c)
        let key = try tlv(outer.1, &c)
        try require(key.0 == 4, "Invalid PKCS#8 key")
        der = key.1
    }
    defer {
        der.resetBytes(in: 0..<der.count)
    }
    var error: Unmanaged<CFError>?
    guard
        let key = SecKeyCreateWithData(
            der as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
                as CFDictionary, &error)
    else {
        throw Failure(message: "RSA import failed")
    }
    let attrs = SecKeyCopyAttributes(key)! as NSDictionary
    try require(
        attrs[kSecAttrKeySizeInBits] as? Int == 3072,
        "Signing key must be the existing RSA-3072 key")
    return key
}

func publicHash(_ pem: Data) throws -> String {
    let key = try rsa(pem)
    guard let pub = SecKeyCopyPublicKey(key), let der = SecKeyCopyExternalRepresentation(pub, nil)
    else {
        throw Failure(message: "Cannot derive public key")
    }
    return hash(der as Data)
}

func sign(_ pem: Data, _ data: Data) throws -> Data {
    let key = try rsa(pem)
    let digest = Data(SHA256.hash(data: data))
    guard let sig = SecKeyCreateSignature(key, .rsaSignatureDigestPSSSHA256, digest as CFData, nil)
    else {
        throw Failure(message: "RSA-PSS signing failed")
    }
    let pub = SecKeyCopyPublicKey(key)!
    try require(
        SecKeyVerifySignature(pub, .rsaSignatureDigestPSSSHA256, digest as CFData, sig, nil),
        "Signature self-verification failed")
    return sig as Data
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

struct AttestationIdentity {
    let certificateSHA256: String
    let publicKeyX963SHA256: String
}
let attestationPayloadSize = 4096
let attestationCertificateLimit = 1024  // Trussed MAX_MESSAGE_LENGTH, not the sector capacity.
let attestationAddress: UInt32 = 0x200000

func derElement(_ data: Data, cursor: inout Int) throws -> (tag: UInt8, value: Data) {
    try require(cursor + 2 <= data.count, "Truncated attestation DER")
    let tag = data[cursor]
    cursor += 1
    var length = Int(data[cursor])
    cursor += 1
    if length & 128 != 0 {
        let count = length & 127
        try require(
            count > 0 && count <= 2 && cursor + count <= data.count && data[cursor] != 0,
            "Invalid attestation DER length")
        length = 0
        for _ in 0..<count {
            length = length * 256 + Int(data[cursor])
            cursor += 1
        }
        try require(
            length >= 128 && (count == 1 || length >= 256), "Noncanonical attestation DER length")
    }
    try require(cursor + length <= data.count, "Truncated attestation DER value")
    let value = Data(data[cursor..<cursor + length])
    cursor += length
    return (tag, value)
}

func validateAttestationAAGUID(_ certificate: Data) throws {
    // Walk real X.509 extension nodes; an OID-shaped sequence in a subject or
    // another extension must never satisfy the identity check.
    var cursor = 0
    let outer = try derElement(certificate, cursor: &cursor)
    try require(outer.tag == 0x30 && cursor == certificate.count, "Invalid certificate sequence")
    cursor = 0
    let tbs = try derElement(outer.value, cursor: &cursor)
    try require(tbs.tag == 0x30, "Invalid certificate TBS sequence")
    cursor = 0
    var extensionBlocks = 0
    var matches = 0
    let oid = Data([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04])
    let expected = Data([
        0x04, 0x10, 0x98, 0x9e, 0x2c, 0xc2, 0x05, 0xdf, 0x4e, 0x64, 0x80, 0x68, 0x22, 0x68, 0x38,
        0x86, 0xe8, 0xb3
    ])
    while cursor < tbs.value.count {
        let node = try derElement(tbs.value, cursor: &cursor)
        if node.tag != 0xa3 {
            continue
        }
        extensionBlocks += 1
        var explicitCursor = 0
        let extensions = try derElement(node.value, cursor: &explicitCursor)
        try require(
            extensions.tag == 0x30 && explicitCursor == node.value.count,
            "Invalid certificate extensions")
        var extCursor = 0
        while extCursor < extensions.value.count {
            let ext = try derElement(extensions.value, cursor: &extCursor)
            try require(ext.tag == 0x30, "Invalid certificate extension")
            var fieldCursor = 0
            let extOID = try derElement(ext.value, cursor: &fieldCursor)
            try require(extOID.tag == 0x06, "Invalid certificate extension OID")
            if extOID.value != oid {
                continue
            }
            matches += 1
            let value = try derElement(ext.value, cursor: &fieldCursor)
            // FIDO AAGUID is noncritical. DER omits its DEFAULT FALSE flag.
            try require(
                value.tag == 0x04 && value.value == expected && fieldCursor == ext.value.count,
                "Certificate has an invalid development AAGUID extension")
        }
    }
    try require(
        extensionBlocks == 1 && matches == 1,
        "Certificate must contain exactly one development AAGUID extension")
}

func validateAttestation(_ raw: Data, _ certificate: Data) throws -> AttestationIdentity {
    try require(
        raw.count == 32 && !certificate.isEmpty && certificate.count <= attestationCertificateLimit,
        "Invalid attestation key or certificate size")
    // Security may tolerate a trailing suffix. Require one complete DER SEQUENCE.
    try require(
        certificate.count >= 2 && certificate[0] == 0x30, "Invalid attestation certificate DER")
    var header = 2
    var length = Int(certificate[1])
    if length & 128 != 0 {
        let count = length & 127
        try require(
            count > 0 && count <= 2 && certificate.count >= 2 + count && certificate[2] != 0,
            "Invalid certificate DER length")
        length = 0
        for i in 0..<count {
            length = length * 256 + Int(certificate[2 + i])
        }
        header += count
        try require(
            length >= 128 && (count == 1 || length >= 256), "Noncanonical certificate DER length")
    }
    try require(
        header + length == certificate.count, "Certificate DER has trailing or missing bytes")
    try validateAttestationAAGUID(certificate)
    guard let cert = SecCertificateCreateWithData(nil, certificate as CFData),
        let publicKey = SecCertificateCopyKey(cert),
        let encoded = SecKeyCopyExternalRepresentation(publicKey, nil)
    else {
        throw Failure(message: "Cannot read attestation certificate public key")
    }
    let attrs = SecKeyCopyAttributes(publicKey)! as NSDictionary
    try require(
        attrs[kSecAttrKeyType] as? String == kSecAttrKeyTypeECSECPrimeRandom as String
            && attrs[kSecAttrKeySizeInBits] as? Int == 256, "Attestation certificate must use P-256"
    )
    let privateKey = try P256.Signing.PrivateKey(rawRepresentation: raw)
    let publicBytes = encoded as Data
    try require(
        publicBytes.count == 65 && privateKey.publicKey.x963Representation == publicBytes,
        "Attestation private key does not match certificate")
    let verifier = try P256.Signing.PublicKey(x963Representation: publicBytes)
    let challenge = try random(64)
    try require(
        verifier.isValidSignature(privateKey.signature(for: challenge), for: challenge),
        "Attestation P-256 sign/verify failed")
    return AttestationIdentity(
        certificateSHA256: hash(certificate), publicKeyX963SHA256: hash(publicBytes))
}

func makeAttestationPayload(_ raw: Data, _ certificate: Data) throws -> Data {
    _ = try validateAttestation(raw, certificate)
    var payload = Data(repeating: 0, count: attestationPayloadSize)
    payload.replaceSubrange(0..<8, with: Data("RKATST01".utf8))
    for i in 0..<4 {
        payload[8 + i] = UInt8(truncatingIfNeeded: certificate.count >> (8 * i))
    }
    payload.replaceSubrange(16..<48, with: raw)
    payload.replaceSubrange(48..<48 + certificate.count, with: certificate)
    return payload
}

func validateAttestationPayload(_ payload: Data) throws -> AttestationIdentity {
    try require(
        payload.count == attestationPayloadSize && payload.prefix(8) == Data("RKATST01".utf8),
        "Invalid attestation payload")
    let length = (0..<4).reduce(UInt32(0)) { $0 | UInt32(payload[8 + $1]) << (8 * $1) }
    try require(
        length > 0 && length <= attestationCertificateLimit
            && payload[12..<16].allSatisfy { $0 == 0 }, "Invalid attestation payload header")
    let end = 48 + Int(length)
    try require(payload[end...].allSatisfy { $0 == 0 }, "Invalid attestation payload padding")
    var raw = Data(payload[16..<48])
    defer {
        raw.resetBytes(in: 0..<raw.count)
    }
    return try validateAttestation(raw, Data(payload[48..<end]))
}

func attestationRecord() throws -> [String: Any] {
    let root = try readRegistry()
    guard let keys = root["keys"] as? [String: Any],
        let record = keys[attestationRole] as? [String: Any]
    else {
        throw Failure(message: "Missing development attestation inventory")
    }
    return record
}

func requireAttestationInventory(_ identity: AttestationIdentity, record: [String: Any]) throws {
    try require(
        record["certificate_sha256"] as? String == identity.certificateSHA256
            && record["public_key_x963_sha256"] as? String == identity.publicKeyX963SHA256,
        "Attestation does not match the imported certificate and public key")
}

func importAttestation(_ keyPath: String, _ certPath: String) throws {
    var raw = try readFile(keyPath, secret: true, max: 32)
    defer {
        raw.resetBytes(in: 0..<raw.count)
    }
    let cert = try readFile(certPath, max: attestationCertificateLimit)
    var payload = try makeAttestationPayload(raw, cert)
    defer {
        payload.resetBytes(in: 0..<payload.count)
    }
    try importData(attestationRole, payload, reference: keyPath)
    try registry(attestationRole, ["original_certificate_copy": certPath], preserveExisting: true)
}

func aes(_ block: [UInt8], _ key: [UInt8], decrypt: Bool = false) throws -> [UInt8] {
    var output = [UInt8](repeating: 0, count: 32)
    var length = 0
    let result = CCCrypt(
        CCOperation(decrypt ? kCCDecrypt : kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
        CCOptions(kCCOptionECBMode), key, key.count, nil, block, block.count, &output, output.count,
        &length)
    try require(result == kCCSuccess && length == 16, "AES operation failed")
    return Array(output.prefix(16))
}

func xts(_ data: Data, _ key: Data, address: UInt32, decrypt: Bool) throws -> Data {
    try require(
        key.count == 32 && !data.isEmpty && data.count % 16 == 0 && address % 16 == 0
            && UInt64(address) + UInt64(data.count) <= 0x100000000, "Invalid AES-XTS input")
    let left = Int(address % 128)
    var input = [UInt8](repeating: 0, count: left) + Array(data)
    input += [UInt8](repeating: 0, count: (128 - input.count % 128) % 128)
    let k1 = Array(key.prefix(16))
    let k2 = Array(key.suffix(16))
    var output = [UInt8]()
    output.reserveCapacity(input.count)
    for pos in stride(from: 0, to: input.count, by: 128) {
        let addr = (address & ~127) + UInt32(pos)
        let raw =
            (0..<4).map { UInt8(truncatingIfNeeded: addr >> ($0 * 8)) }
            + [UInt8](repeating: 0, count: 12)
        var tweak = try aes(raw, k2)
        let block = Array(input[pos..<pos + 128].reversed())
        var result = [UInt8]()
        for j in stride(from: 0, to: 128, by: 16) {
            let x = (0..<16).map { block[j + $0] ^ tweak[$0] }
            let y = try aes(x, k1, decrypt: decrypt)
            result += (0..<16).map { y[$0] ^ tweak[$0] }
            var carry: UInt8 = 0
            for i in 0..<16 {
                let next = tweak[i] >> 7
                tweak[i] = (tweak[i] << 1) | carry
                carry = next
            }
            if carry != 0 {
                tweak[0] ^= 0x87
            }
        }
        output += result.reversed()
    }
    return Data(output[left..<left + data.count])
}

func random(_ n: Int) throws -> Data {
    var d = Data(count: n)
    let status = d.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!)
    }
    try check(status)
    return d
}

func password(_ title: String, confirm: Bool) throws -> Data {
    NSApplication.shared.setActivationPolicy(.accessory)
    NSApp.activate(ignoringOtherApps: true)
    while true {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText =
            confirm
            ? """
            Create a NEW backup passphrase, separate from your macOS password. \
            Use at least 20 characters, for example a long phrase of several \
            words. Keep it separately from the backup. Enter the same phrase in \
            both fields. Salpa does not save it.
            """
            : "Re-enter the backup passphrase. It is used only in this process and is not saved."
        alert.icon = NSImage(
            systemSymbolName: "key.fill", accessibilityDescription: "Salpa backup")
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: confirm ? 70 : 30))
        let field = NSSecureTextField(
            frame: NSRect(x: 0, y: confirm ? 40 : 0, width: 420, height: 24))
        field.placeholderString = "Backup passphrase (at least 20 characters)"
        view.addSubview(field)
        let second = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        if confirm {
            second.placeholderString = "Repeat the same passphrase"
            view.addSubview(second)
        }
        alert.accessoryView = view
        alert.window.initialFirstResponder = field
        try require(alert.runModal() == .alertFirstButtonReturn, "Cancelled")
        defer {
            field.stringValue = ""
            second.stringValue = ""
        }
        if field.stringValue.count < 20 || (confirm && field.stringValue != second.stringValue) {
            let tooShort = field.stringValue.count < 20
            field.stringValue = ""
            second.stringValue = ""
            let warning = NSAlert()
            warning.messageText = "Salpa: backup passphrase"
            warning.informativeText =
                tooShort
                ? """
                The new backup passphrase is too short. Use at least 20 characters. \
                This is separate from the macOS password that you used earlier.
                """
                : """
                The two backup passphrases do not match. Enter exactly the same new \
                passphrase in both fields.
                """
            warning.addButton(withTitle: "Try again")
            warning.runModal()
            continue
        }
        return Data(field.stringValue.utf8)
    }
}

func derive(_ password: Data, _ salt: Data) throws -> SymmetricKey {
    var key = Data(count: 32)
    defer {
        key.resetBytes(in: 0..<key.count)
    }
    let status = key.withUnsafeMutableBytes { out in
        password.withUnsafeBytes { pass in
            salt.withUnsafeBytes { salt in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pass.baseAddress!.assumingMemoryBound(to: Int8.self), pass.count,
                    salt.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600000,
                    out.baseAddress!.assumingMemoryBound(to: UInt8.self), out.count)
            }
        }
    }
    try require(status == kCCSuccess, "Backup key derivation failed")
    return SymmetricKey(data: key)
}

struct Envelope: Codable {
    let format: String
    let role: String
    let publicKeySHA256: String
    let salt: Data
    let sealed: Data
}

func backup(_ destination: String) throws {
    var secret = try loadKey("signing")
    defer {
        secret.resetBytes(in: 0..<secret.count)
    }
    var pass = try password("Salpa: create encrypted signing-key backup", confirm: true)
    defer {
        pass.resetBytes(in: 0..<pass.count)
    }
    let salt = try random(32)
    let fingerprint = try publicHash(secret)
    let aad = Data(("rissokey-backup-v1|signing|" + fingerprint).utf8)
    let box = try AES.GCM.seal(secret, using: derive(pass, salt), authenticating: aad)
    let envelope = Envelope(
        format: "rissokey-backup-v1-pbkdf2-sha256-600000-aes256gcm", role: "signing",
        publicKeySHA256: fingerprint, salt: salt, sealed: box.combined!)
    try writeNew(JSONEncoder().encode(envelope), destination)
    try registry(
        "signing",
        [
            "backup_location_reference": destination, "backup_created_at": now(),
            "backup_status": "encrypted; restore pending; external staging location is connected",
            "passphrase_location": "owner instructed to retain separately; never stored by helper"
        ])
}

func openBackup(_ path: String) throws -> (Data, Envelope, Data) {
    let file = try readFile(path, secret: true, max: 65536)
    let envelope = try JSONDecoder().decode(Envelope.self, from: file)
    try require(
        envelope.format == "rissokey-backup-v1-pbkdf2-sha256-600000-aes256gcm"
            && envelope.role == "signing" && envelope.salt.count == 32, "Unsupported backup")
    var pass = try password("Salpa: verify backup restoration", confirm: false)
    defer {
        pass.resetBytes(in: 0..<pass.count)
    }
    let aad = Data(("rissokey-backup-v1|signing|" + envelope.publicKeySHA256).utf8)
    var secret = try AES.GCM.open(
        AES.GCM.SealedBox(combined: envelope.sealed), using: derive(pass, envelope.salt),
        authenticating: aad)
    try require(try publicHash(secret) == envelope.publicKeySHA256, "Backup public key mismatch")
    return (secret, envelope, file)
}

func restoreTest(_ path: String) throws {
    var (secret, envelope, file) = try openBackup(path)
    defer {
        secret.resetBytes(in: 0..<secret.count)
    }
    // Match the restored key to the local inventory recorded during import.
    let root = try readRegistry()
    guard let keys = root["keys"] as? [String: Any], let record = keys["signing"] as? [String: Any]
    else {
        throw Failure(message: "Missing signing-key inventory")
    }
    try require(
        record["public_key_pkcs1_sha256"] as? String == envelope.publicKeySHA256,
        "Backup does not match the imported signing root")
    _ = try sign(secret, random(64))
    try registry(
        "signing",
        [
            "restore_test_at": now(), "backup_location_reference": path,
            "backup_sha256": hash(file),
            "backup_status":
                "in-memory restore and RSA sign/verify passed; offline separation still required"
        ])
}
let attestationBackupFormat = "rissokey-attestation-backup-v1-pbkdf2-sha256-600000-aes256gcm"

struct AttestationEnvelope: Codable {
    let format: String
    let role: String
    let certificateSHA256: String
    let publicKeyX963SHA256: String
    let salt: Data
    let sealed: Data
}

func isSHA256(_ text: String) -> Bool {
    text.utf8.count == 64
        && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}

func attestationAAD(_ envelope: AttestationEnvelope) -> Data {
    Data(
        [envelope.format, envelope.role, envelope.certificateSHA256, envelope.publicKeyX963SHA256]
            .joined(separator: "|").utf8)
}

func sealAttestationBackup(_ payload: Data, pass: Data, salt: Data) throws -> AttestationEnvelope {
    let identity = try validateAttestationPayload(payload)
    try require(salt.count == 32, "Invalid attestation backup salt")
    let header = AttestationEnvelope(
        format: attestationBackupFormat, role: attestationRole,
        certificateSHA256: identity.certificateSHA256,
        publicKeyX963SHA256: identity.publicKeyX963SHA256, salt: salt, sealed: Data())
    let box = try AES.GCM.seal(
        payload, using: derive(pass, salt), authenticating: attestationAAD(header))
    return AttestationEnvelope(
        format: header.format, role: header.role, certificateSHA256: header.certificateSHA256,
        publicKeyX963SHA256: header.publicKeyX963SHA256, salt: salt, sealed: box.combined!)
}

func openAttestationEnvelope(_ envelope: AttestationEnvelope, pass: Data) throws -> Data {
    try require(
        envelope.format == attestationBackupFormat && envelope.role == attestationRole
            && envelope.salt.count == 32 && envelope.sealed.count == attestationPayloadSize + 28
            && isSHA256(envelope.certificateSHA256) && isSHA256(envelope.publicKeyX963SHA256),
        "Unsupported attestation backup")
    var payload = try AES.GCM.open(
        AES.GCM.SealedBox(combined: envelope.sealed), using: derive(pass, envelope.salt),
        authenticating: attestationAAD(envelope))
    var accepted = false
    defer {
        if !accepted {
            payload.resetBytes(in: 0..<payload.count)
        }
    }
    let identity = try validateAttestationPayload(payload)
    try require(
        identity.certificateSHA256 == envelope.certificateSHA256
            && identity.publicKeyX963SHA256 == envelope.publicKeyX963SHA256,
        "Attestation backup identity mismatch")
    accepted = true
    return payload
}

func requireAttestationRecoveryReference(_ envelope: AttestationEnvelope, reference: Data) throws {
    // This file must be an independently retained manifest/reference. The
    // backup's own authenticated metadata is not an independent trust anchor.
    guard let object = try JSONSerialization.jsonObject(with: reference) as? [String: Any],
        let expected = object["certificate_sha256"] as? String, isSHA256(expected)
    else {
        throw Failure(message: "Recovery requires an independent certificate_sha256 reference")
    }
    try require(
        envelope.format == attestationBackupFormat && envelope.role == attestationRole
            && envelope.certificateSHA256 == expected,
        "Backup does not match the independently retained attestation certificate")
    if let publicReference = object["public_key_x963_sha256"] {
        guard let expectedPublic = publicReference as? String, isSHA256(expectedPublic),
            expectedPublic == envelope.publicKeyX963SHA256
        else {
            throw Failure(
                message: "Backup does not match the independently retained attestation public key")
        }
    }
}

func prepareAttestationRecovery(_ envelope: AttestationEnvelope, reference: Data, pass: Data) throws
    -> Data
{
    try requireAttestationRecoveryReference(envelope, reference: reference)
    // Opening checks the certificate, AAGUID, scalar/public pair and envelope
    // bindings. No local inventory or existing Keychain item is needed here.
    return try openAttestationEnvelope(envelope, pass: pass)
}

func restoreAttestation(_ backupPath: String, _ referencePath: String) throws {
    let file = try readFile(backupPath, secret: true, max: 16384)
    let reference = try readFile(referencePath, max: 16384)
    let envelope = try JSONDecoder().decode(AttestationEnvelope.self, from: file)
    try requireAttestationRecoveryReference(envelope, reference: reference)
    var pass = try password("Salpa: restore development FIDO attestation", confirm: false)
    defer {
        pass.resetBytes(in: 0..<pass.count)
    }
    var payload = try prepareAttestationRecovery(envelope, reference: reference, pass: pass)
    defer {
        payload.resetBytes(in: 0..<payload.count)
    }
    try authenticate(
        """
        restore the independently identified Salpa development FIDO \
        attestation into the local Keychain
        """
    )
    // SecItemAdd plus an authenticated equality check refuses any replacement.
    try importData(attestationRole, payload, reference: backupPath)
    try registry(
        attestationRole,
        [
            "restored_at": now(), "recovery_reference_path": referencePath,
            "recovery_reference_sha256": hash(reference), "backup_location_reference": backupPath,
            "backup_sha256": hash(file), "backup_registered_at": now(),
            "backup_process_session": processSession,
            "backup_status": "restored into local Keychain; separate-process restore test pending",
            "restore_test_at": NSNull(), "restore_test_process_session": NSNull(),
            "restore_test_backup_sha256": NSNull(),
            "status":
                """
            restored from independently bound encrypted backup; separate-process \
            restore test required before staging
            """
        ])
}

func backupAttestation(_ destination: String) throws {
    var payload = try loadKey(attestationRole)
    defer {
        payload.resetBytes(in: 0..<payload.count)
    }
    try requireAttestationInventory(
        validateAttestationPayload(payload), record: attestationRecord())
    var pass = try password("Salpa: create encrypted FIDO attestation backup", confirm: true)
    defer {
        pass.resetBytes(in: 0..<pass.count)
    }
    let envelope = try sealAttestationBackup(payload, pass: pass, salt: random(32))
    let file = try JSONEncoder().encode(envelope)
    try writeNew(file, destination)
    try registry(
        attestationRole,
        [
            "backup_location_reference": destination, "backup_sha256": hash(file),
            "backup_created_at": now(), "backup_process_session": processSession,
            "backup_status": "encrypted; separate-process restoration test required",
            "restore_test_at": NSNull(), "restore_test_backup_sha256": NSNull(),
            "passphrase_location": "owner instructed to retain separately; never stored by helper"
        ])
}

func requireFreshAttestationRestore(record: [String: Any]) throws {
    guard let session = record["backup_process_session"] as? String, !session.isEmpty,
        session != processSession
    else {
        throw Failure(
            message:
                """
                Attestation restore test must run in a new helper process after \
                backup creation or recovery registration
                """
        )
    }
}

func restoreTestAttestation(_ path: String) throws {
    let record = try attestationRecord()
    try requireFreshAttestationRestore(record: record)
    let file = try readFile(path, secret: true, max: 16384)
    let envelope = try JSONDecoder().decode(AttestationEnvelope.self, from: file)
    try require(
        record["backup_sha256"] as? String == hash(file),
        "Attestation backup differs from the recorded encrypted backup")
    // Reject another identity before asking for the passphrase.
    try requireAttestationInventory(
        AttestationIdentity(
            certificateSHA256: envelope.certificateSHA256,
            publicKeyX963SHA256: envelope.publicKeyX963SHA256), record: record)
    var pass = try password("Salpa: restore-test development FIDO attestation", confirm: false)
    defer {
        pass.resetBytes(in: 0..<pass.count)
    }
    var payload = try openAttestationEnvelope(envelope, pass: pass)
    defer {
        payload.resetBytes(in: 0..<payload.count)
    }
    try requireAttestationInventory(validateAttestationPayload(payload), record: record)
    try registry(
        attestationRole,
        [
            "restore_test_at": now(), "restore_test_process_session": processSession,
            "restore_test_backup_sha256": hash(file), "backup_location_reference": path,
            "backup_status":
                """
            separate-process in-memory restore and P-256 certificate sign/verify \
            passed; retain backup separately
            """
        ])
}

func requireAttestationRecovery(record: [String: Any], backupFile: Data) throws {
    guard let backupHash = record["backup_sha256"] as? String, isSHA256(backupHash),
        let restoredAt = record["restore_test_at"] as? String, !restoredAt.isEmpty,
        let createdSession = record["backup_process_session"] as? String,
        let restoredSession = record["restore_test_process_session"] as? String
    else {
        throw Failure(
            message: "Attestation encrypted backup and restore test are required before staging")
    }
    try require(
        !createdSession.isEmpty && !restoredSession.isEmpty && createdSession != restoredSession
            && record["restore_test_backup_sha256"] as? String == backupHash
            && hash(backupFile) == backupHash,
        "Attestation backup has not passed an independent restore test or has changed")
    let envelope = try JSONDecoder().decode(AttestationEnvelope.self, from: backupFile)
    try require(
        envelope.format == attestationBackupFormat && envelope.role == attestationRole,
        "Invalid attestation recovery backup role")
    try requireAttestationInventory(
        AttestationIdentity(
            certificateSHA256: envelope.certificateSHA256,
            publicKeyX963SHA256: envelope.publicKeyX963SHA256), record: record)
}

func stageAttestation(_ destination: String) throws {
    let record = try attestationRecord()
    guard let backupPath = record["backup_location_reference"] as? String else {
        throw Failure(message: "Missing encrypted attestation backup")
    }
    try requireAttestationRecovery(
        record: record, backupFile: readFile(backupPath, secret: true, max: 16384))
    var payload = try loadKey(
        attestationRole,
        reason:
            "prepare the ESP32-S2 development FIDO attestation for encrypted provisioning")
    defer {
        payload.resetBytes(in: 0..<payload.count)
    }
    try requireAttestationInventory(validateAttestationPayload(payload), record: record)
    var flashKey = try loadKey(
        "flash",
        reason:
            "encrypt the 4096-byte FIDO attestation provisioning sector at flash address 0x200000")
    defer {
        flashKey.resetBytes(in: 0..<flashKey.count)
    }
    let ciphertext = try xts(payload, flashKey, address: attestationAddress, decrypt: false)
    var roundtrip = try xts(ciphertext, flashKey, address: attestationAddress, decrypt: true)
    defer {
        roundtrip.resetBytes(in: 0..<roundtrip.count)
    }
    try require(roundtrip == payload, "Attestation staging AES-XTS roundtrip failed")
    try writeNew(ciphertext, destination)
    try registry(
        attestationRole,
        [
            "last_staged_at": now(), "staging_ciphertext_sha256": hash(ciphertext),
            "staging_address": "0x200000", "staging_length": attestationPayloadSize,
            "staging_output_reference": destination,
            "status":
                """
            ciphertext prepared; physical provisioning and encrypted \
            staging-sector erasure remain pending
            """
        ])
}

func main() throws {
    umask(0o077)
    var limit = rlimit(rlim_cur: 0, rlim_max: 0)
    try require(setrlimit(RLIMIT_CORE, &limit) == 0, "Cannot disable core dumps")
    let args = Array(CommandLine.arguments.dropFirst())
    guard let command = args.first else {
        throw Failure(
            message:
                """
                Commands: import ROLE FILE | status ROLE | sign INPUT OUTPUT | \
                encrypt ADDRESS INPUT OUTPUT | backup FILE | restore-test FILE | \
                import-attestation KEY_RAW CERT_DER | backup-attestation FILE | \
                restore-attestation BACKUP ORIGINAL_REFERENCE_JSON | \
                restore-test-attestation FILE | stage-attestation OUTPUT
                """
        )
    }
    switch command {
    case "import":
        try require(
            args.count == 3 && ["signing", "flash"].contains(args[1]),
            "Usage: import signing|flash FILE")
        try importKey(args[1], args[2])
    case "import-attestation":
        try require(args.count == 3, "Usage: import-attestation KEY_RAW CERT_DER")
        try importAttestation(args[1], args[2])
    case "backup-attestation":
        try require(args.count == 2, "Usage: backup-attestation FILE")
        try backupAttestation(args[1])
    case "restore-attestation":
        try require(args.count == 3, "Usage: restore-attestation BACKUP ORIGINAL_REFERENCE_JSON")
        try restoreAttestation(args[1], args[2])
    case "restore-test-attestation":
        try require(args.count == 2, "Usage: restore-test-attestation FILE")
        try restoreTestAttestation(args[1])
    case "stage-attestation":
        try require(args.count == 2, "Usage: stage-attestation OUTPUT")
        try stageAttestation(args[1])
    case "status":
        try require(args.count == 2, "Usage: status ROLE")
        try noUI(args[1])
        print(
            """
            ACL verified: local login Keychain, no trusted applications, fresh \
            owner authentication required by helper, noninteractive Keychain read \
            denied
            """
        )
    case "sign":
        try require(args.count == 3, "Usage: sign INPUT OUTPUT")
        let data = try readFile(args[1])
        try require(
            data.count % 4096 == 0, "Secure Boot signing input must be padded to 4096 bytes")
        var secret = try loadKey(
            "signing", reason: "sign Salpa firmware with SHA-256 " + hash(data))
        defer {
            secret.resetBytes(in: 0..<secret.count)
        }
        let signature = try sign(secret, data)
        try writeNew(signature, args[2])
        try registry(
            "signing",
            [
                "last_sign_at": now(), "last_signed_sha256": hash(data),
                "status": "interactive signing and ACL checks passed"
            ])
    case "encrypt":
        try require(args.count == 4, "Usage: encrypt ADDRESS INPUT OUTPUT")
        guard
            let address = UInt32(
                args[1].hasPrefix("0x") ? String(args[1].dropFirst(2)) : args[1],
                radix: args[1].hasPrefix("0x") ? 16 : 10)
        else {
            throw Failure(message: "Invalid address")
        }
        let data = try readFile(args[2])
        var key = try loadKey("flash")
        defer {
            key.resetBytes(in: 0..<key.count)
        }
        let encrypted = try xts(data, key, address: address, decrypt: false)
        try require(
            try xts(encrypted, key, address: address, decrypt: true) == data,
            "AES-XTS roundtrip failed")
        try writeNew(encrypted, args[3])
        try registry(
            "flash",
            [
                "last_encryption_at": now(),
                "status":
                    "interactive encryption and roundtrip passed; retain original for recovery"
            ])
    case "backup":
        try require(args.count == 2, "Usage: backup FILE")
        try backup(args[1])
    case "restore":
        try require(args.count == 3, "Usage: restore BACKUP EXPECTED_PUBLIC_PKCS1_SHA256")
        var (secret, envelope, _) = try openBackup(args[1])
        defer {
            secret.resetBytes(in: 0..<secret.count)
        }
        try require(
            args[2].count == 64 && args[2] == envelope.publicKeySHA256,
            "Backup does not match the independently expected public root")
        try authenticate(
            "restore the existing Salpa firmware signing key into the local Keychain")
        try importData("signing", secret, reference: args[1])
        try registry(
            "signing",
            [
                "status": "restored from encrypted backup; interactive signing must be reverified",
                "backup_location_reference": args[1], "restored_at": now()
            ])
    case "restore-test":
        try require(args.count == 2, "Usage: restore-test FILE")
        try restoreTest(args[1])
    default: throw Failure(message: "Unsupported command")
    }
}
#if !KEY_HELPER_TEST
    do {
        try main()
    } catch let error as Failure {
        fputs("Salpa: \(error.message)\n", stderr)
        exit(1)
    } catch {
        fputs("Salpa: operation failed; no secret details are logged\n", stderr)
        exit(1)
    }

#endif
