// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
