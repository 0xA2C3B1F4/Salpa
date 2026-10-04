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
