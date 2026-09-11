// Compiled only by the separate host test runner; never installed.

func rejects(_ label: String, _ action: () throws -> Void) throws {
    var rejected = false
    do {
        try action()
    } catch {
        rejected = true
    }
    try require(rejected, label)
}

do {
    let fixtureFolder = CommandLine.arguments[1]
    if CommandLine.arguments.count == 3 && CommandLine.arguments[2] == "restore-attestation-fixture"
    {
        let envelope = try JSONDecoder().decode(
            AttestationEnvelope.self, from: readFile(fixtureFolder + "/attestation-backup.json"))
        var restored = try openAttestationEnvelope(
            envelope, pass: Data("test-only-public-passphrase".utf8))
        defer {
            restored.resetBytes(in: 0..<restored.count)
        }
        try require(
            restored == readFile(fixtureFolder + "/attestation-payload.bin"),
            "Separate-process restore mismatch")
        let record =
            try JSONSerialization.jsonObject(
                with: readFile(fixtureFolder + "/attestation-record.json")) as! [String: Any]
        try requireFreshAttestationRestore(record: record)
        try requireAttestationInventory(validateAttestationPayload(restored), record: record)
        print("PASS: fresh-process attestation restore and independent inventory binding")
        exit(0)
    }
    let key = Data((0..<32).map { UInt8($0) })
    let payload = Data((0..<256).map { UInt8($0) })
    for address: UInt32 in [0, 16, 112, 0x1000, 0x20000, 0x200000] {
        let encrypted = try xts(payload, key, address: address, decrypt: false)
        try require(
            try xts(encrypted, key, address: address, decrypt: true) == payload, "XTS roundtrip")
        let expected = try readFile(CommandLine.arguments[1] + "/xts-\(address).bin")
        try require(encrypted == expected, "XTS does not match espsecure")
    }
    let pass = Data("test-only-public-passphrase".utf8)
    let salt = Data(repeating: 42, count: 32)
    let derived = try derive(pass, salt)
    let expectedDerived = try readFile(CommandLine.arguments[1] + "/pbkdf2.bin")
    try require(
        derived.withUnsafeBytes { Data($0) } == expectedDerived, "PBKDF2 does not match Python")
    let box = try AES.GCM.seal(payload, using: derived, authenticating: Data("test".utf8))
    try require(
        try AES.GCM.open(box, using: derived, authenticating: Data("test".utf8)) == payload,
        "Backup roundtrip")
    var rejected = false
    do {
        _ = try AES.GCM.open(
            box, using: derive(Data("wrong test password".utf8), salt),
            authenticating: Data("test".utf8))
    } catch {
        rejected = true
    }
    try require(rejected, "Wrong backup password accepted")
    rejected = false
    do {
        _ = try AES.GCM.open(box, using: derived, authenticating: Data("altered".utf8))
    } catch {
        rejected = true
    }
    try require(rejected, "Altered backup metadata accepted")
    var damaged = box.combined!
    damaged[20] ^= 1
    rejected = false
    do {
        _ = try AES.GCM.open(
            AES.GCM.SealedBox(combined: damaged), using: derived, authenticating: Data("test".utf8))
    } catch {
        rejected = true
    }
    try require(rejected, "Corrupt backup accepted")
    let pem = try readFile(CommandLine.arguments[1] + "/test-key.pem", secret: true)
    let sig = try sign(pem, payload)
    try writeNew(sig, CommandLine.arguments[1] + "/test.sig")
    let certificate = try readFile(fixtureFolder + "/fixture-1.der")
    var fixtureRaw = Data(repeating: 0, count: 32)
    fixtureRaw[31] = 1
    var attestationPayload = try makeAttestationPayload(fixtureRaw, certificate)
    defer {
        fixtureRaw.resetBytes(in: 0..<fixtureRaw.count)
        attestationPayload.resetBytes(in: 0..<attestationPayload.count)
    }
    try require(
        attestationPayload == readFile(fixtureFolder + "/attestation-payload.bin"),
        "Wrong staging byte layout")
    try require(
        try xts(attestationPayload, key, address: attestationAddress, decrypt: false)
            == readFile(fixtureFolder + "/attestation-xts.bin"),
        "Attestation staging differs from espsecure")
    let identity = try validateAttestationPayload(attestationPayload)
    try rejects("Mismatched P-256 pair accepted") {
        _ = try validateAttestation(fixtureRaw, readFile(fixtureFolder + "/fixture-2.der"))
    }
    for scalar: UInt8 in [3, 4, 5] {
        var matchingRaw = Data(repeating: 0, count: 32)
        matchingRaw[31] = scalar
        try rejects("Wrong, missing or critical AAGUID accepted") {
            _ = try validateAttestation(
                matchingRaw, readFile(fixtureFolder + "/fixture-\(scalar).der"))
        }
        matchingRaw.resetBytes(in: 0..<matchingRaw.count)
    }
    try rejects("Zero private scalar accepted") {
        _ = try validateAttestation(Data(repeating: 0, count: 32), certificate)
    }
    try rejects("Trailing certificate bytes accepted") {
        _ = try validateAttestation(fixtureRaw, certificate + Data([0]))
    }
    try rejects("Oversized certificate accepted") {
        _ = try validateAttestation(fixtureRaw, Data(repeating: 0, count: 1025))
    }
    try rejects("Short payload accepted") {
        _ = try validateAttestationPayload(Data(attestationPayload.dropLast()))
    }
    for position in [0, 8, 12, 4095] {
        var altered = attestationPayload
        altered[position] ^= 1
        try rejects("Malformed staging payload accepted") {
            _ = try validateAttestationPayload(altered)
        }
        altered.resetBytes(in: 0..<altered.count)
    }
    let envelope = try sealAttestationBackup(attestationPayload, pass: pass, salt: salt)
    let recoveryReference = try JSONSerialization.data(withJSONObject: [
        "certificate_sha256": identity.certificateSHA256
    ])
    var prepared = try prepareAttestationRecovery(
        envelope, reference: recoveryReference, pass: pass)
    try require(prepared == attestationPayload, "New-machine recovery preparation failed")
    prepared.resetBytes(in: 0..<prepared.count)
    for reference: [String: Any] in [
        [:], ["certificate_sha256": String(repeating: "0", count: 64)],
        ["certificate_sha256": "invalid"],
        [
            "certificate_sha256": identity.certificateSHA256,
            "public_key_x963_sha256": String(repeating: "0", count: 64)
        ]
    ] {
        let data = try JSONSerialization.data(withJSONObject: reference)
        try rejects("Missing or incorrect independent recovery reference accepted") {
            _ = try prepareAttestationRecovery(envelope, reference: data, pass: pass)
        }
    }
    try rejects("Backup accepted as its own independent reference") {
        _ = try prepareAttestationRecovery(
            envelope, reference: JSONEncoder().encode(envelope), pass: pass)
    }
    let fullReference = try JSONSerialization.data(withJSONObject: [
        "certificate_sha256": identity.certificateSHA256,
        "public_key_x963_sha256": identity.publicKeyX963SHA256
    ])
    try requireAttestationRecoveryReference(envelope, reference: fullReference)
    var restored = try openAttestationEnvelope(envelope, pass: pass)
    try require(restored == attestationPayload, "Attestation backup roundtrip failed")
    restored.resetBytes(in: 0..<restored.count)
    try rejects("Wrong attestation password accepted") {
        _ = try openAttestationEnvelope(envelope, pass: Data("different test-only password".utf8))
    }
    for change in ["role", "format", "certificateSHA256", "publicKeyX963SHA256", "salt", "sealed"] {
        var object =
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(envelope)) as! [String: Any]
        if ["certificateSHA256", "publicKeyX963SHA256"].contains(change) {
            object[change] = String(repeating: "0", count: 64)
        } else if ["salt", "sealed"].contains(change) {
            var bytes = Data(base64Encoded: object[change] as! String)!
            bytes[0] ^= 1
            object[change] = bytes.base64EncodedString()
        } else {
            object[change] = "signing"
        }
        let altered = try JSONDecoder().decode(
            AttestationEnvelope.self, from: JSONSerialization.data(withJSONObject: object))
        try rejects("Altered attestation backup accepted") {
            _ = try openAttestationEnvelope(altered, pass: pass)
        }
    }
    let file = try JSONEncoder().encode(envelope)
    var record: [String: Any] = [
        "certificate_sha256": identity.certificateSHA256,
        "public_key_x963_sha256": identity.publicKeyX963SHA256,
        "backup_process_session": processSession, "backup_sha256": hash(file)
    ]
    try requireAttestationInventory(identity, record: record)
    try rejects("Wrong certificate inventory accepted") {
        try requireAttestationInventory(
            AttestationIdentity(
                certificateSHA256: String(repeating: "0", count: 64),
                publicKeyX963SHA256: identity.publicKeyX963SHA256), record: record)
    }
    try rejects("Wrong public-key inventory accepted") {
        try requireAttestationInventory(
            AttestationIdentity(
                certificateSHA256: identity.certificateSHA256,
                publicKeyX963SHA256: String(repeating: "0", count: 64)), record: record)
    }
    try rejects("Same-process restore accepted") {
        try requireFreshAttestationRestore(record: record)
    }
    try rejects("Staging without restore accepted") {
        try requireAttestationRecovery(record: record, backupFile: file)
    }
    try writeNew(file, fixtureFolder + "/attestation-backup.json")
    try writeNew(
        JSONSerialization.data(withJSONObject: record), fixtureFolder + "/attestation-record.json")
    record["restore_test_at"] = now()
    record["restore_test_process_session"] = "independent-test-process"
    record["restore_test_backup_sha256"] = hash(file)
    try requireAttestationRecovery(record: record, backupFile: file)
    try rejects("Changed backup accepted for staging") {
        try requireAttestationRecovery(record: record, backupFile: file + Data([0]))
    }
    record["restore_test_process_session"] = processSession
    try rejects("Same-process restoration allowed staging") {
        try requireAttestationRecovery(record: record, backupFile: file)
    }
    print(
        """
        PASS: attestation pair/payload validation, authenticated backup \
        tamper rejection, independent recovery reference, inventory binding \
        and staging recovery gates
        """
    )
    print(
        """
        PASS: six Espressif XTS vectors; PBKDF2 reference; AES-GCM roundtrip, \
        wrong password, metadata and corruption rejection; RSA-PSS self-check
        """
    )
} catch {
    fputs("Key helper crypto test failed\n", stderr)
    exit(1)
}
