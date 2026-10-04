// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
