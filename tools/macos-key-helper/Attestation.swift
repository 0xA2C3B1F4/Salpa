// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
