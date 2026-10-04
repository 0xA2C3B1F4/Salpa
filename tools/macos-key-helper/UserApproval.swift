// Local file-based Keychain: no synchronization, no trusted applications.
import AppKit
import CommonCrypto
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Darwin

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
