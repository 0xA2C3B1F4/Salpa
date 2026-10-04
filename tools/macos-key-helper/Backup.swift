// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
