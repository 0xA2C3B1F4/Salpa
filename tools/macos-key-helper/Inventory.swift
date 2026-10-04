// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
