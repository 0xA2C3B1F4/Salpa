// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
