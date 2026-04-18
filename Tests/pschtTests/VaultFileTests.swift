import Testing
import Foundation
import Crypto
@testable import pscht

@Suite("VaultFile codec")
struct VaultFileTests {
    private func makeKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0x42, count: 32))
    }

    private func zeros(_ n: Int) -> Data { Data(repeating: 0, count: n) }

    @Test("Round-trip preserves plaintext and header fields")
    func roundTrip() throws {
        let key = makeKey()
        let plaintext = Data("top secret".utf8)
        let indexHash = Data(repeating: 0xAA, count: 32)
        let nonce = Data(repeating: 0xBB, count: 12)

        let blob = try VaultFile.seal(
            plaintext: plaintext,
            key: key,
            indexHash: indexHash,
            nonce: nonce
        )
        let (out, header) = try VaultFile.open(blob: blob, key: key)

        #expect(out == plaintext)
        #expect(header.nonce == nonce)
        #expect(header.indexHash == indexHash)
        #expect(header.version == VaultFile.currentVersion)
        #expect(header.suite == VaultFile.suiteChaChaPoly)
        #expect(header.flags == 0)
    }

    @Test("Two seals with different nonces produce different ciphertext")
    func nonceChangesCiphertext() throws {
        let key = makeKey()
        let plaintext = Data("same plaintext".utf8)
        let indexHash = zeros(32)

        let a = try VaultFile.seal(plaintext: plaintext, key: key, indexHash: indexHash,
                                   nonce: Data(repeating: 0x01, count: 12))
        let b = try VaultFile.seal(plaintext: plaintext, key: key, indexHash: indexHash,
                                   nonce: Data(repeating: 0x02, count: 12))
        #expect(a != b)
        #expect(a.suffix(from: VaultFile.headerSize) != b.suffix(from: VaultFile.headerSize))
    }

    @Test("Random nonce is not all zeros")
    func randomNonceNotZero() throws {
        let key = makeKey()
        let blob = try VaultFile.seal(
            plaintext: Data("hi".utf8),
            key: key,
            indexHash: zeros(32)
        )
        let header = try VaultFile.decodeHeader(blob)
        #expect(header.nonce != zeros(12))
    }

    @Test("Tampering with the header fails authentication")
    func headerTampering() throws {
        let key = makeKey()
        var blob = try VaultFile.seal(
            plaintext: Data("data".utf8),
            key: key,
            indexHash: Data(repeating: 0xCC, count: 32)
        )
        // Flip a bit in the index hash (byte 20).
        blob[20] ^= 0x01
        #expect(throws: SecretStoreError.self) {
            try VaultFile.open(blob: blob, key: key)
        }
    }

    @Test("Tampering with the ciphertext fails authentication")
    func ciphertextTampering() throws {
        let key = makeKey()
        var blob = try VaultFile.seal(
            plaintext: Data(repeating: 0xFF, count: 100),
            key: key,
            indexHash: zeros(32)
        )
        // Flip a bit in the middle of the ciphertext.
        let offset = VaultFile.headerSize + 10
        blob[offset] ^= 0x01
        #expect(throws: SecretStoreError.self) {
            try VaultFile.open(blob: blob, key: key)
        }
    }

    @Test("Wrong key fails authentication")
    func wrongKey() throws {
        let right = makeKey()
        let wrong = SymmetricKey(data: Data(repeating: 0xFE, count: 32))
        let blob = try VaultFile.seal(
            plaintext: Data("data".utf8),
            key: right,
            indexHash: zeros(32)
        )
        #expect(throws: SecretStoreError.self) {
            try VaultFile.open(blob: blob, key: wrong)
        }
    }

    @Test("Unknown version rejected")
    func unsupportedVersion() throws {
        let key = makeKey()
        var blob = try VaultFile.seal(
            plaintext: Data("data".utf8),
            key: key,
            indexHash: zeros(32)
        )
        // Bump version byte to 0xFF.
        blob[4] = 0xFF
        #expect(throws: SecretStoreError.self) {
            try VaultFile.open(blob: blob, key: key)
        }
    }

    @Test("Bad magic rejected")
    func badMagic() throws {
        let key = makeKey()
        var blob = try VaultFile.seal(
            plaintext: Data("data".utf8),
            key: key,
            indexHash: zeros(32)
        )
        blob[0] = 0x00
        #expect(throws: SecretStoreError.self) {
            try VaultFile.open(blob: blob, key: key)
        }
    }

    @Test("Atomic write creates file with 0600 perms")
    func atomicWriteCreatesFile() throws {
        let tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pscht-vault-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let target = tmpDir.appendingPathComponent("vault.enc")
        let payload = Data("hello".utf8)
        try VaultFile.atomicWrite(blob: payload, to: target)

        #expect(FileManager.default.fileExists(atPath: target.path))
        let read = try Data(contentsOf: target)
        #expect(read == payload)

        let attrs = try FileManager.default.attributesOfItem(atPath: target.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.int16Value ?? 0
        // On Linux/macOS the file should be 0600 (user-only).
        #expect(perms & 0o077 == 0)
    }

    @Test("Atomic write overwrites existing file")
    func atomicWriteOverwrites() throws {
        let tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pscht-vault-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let target = tmpDir.appendingPathComponent("vault.enc")
        try VaultFile.atomicWrite(blob: Data("first".utf8), to: target)
        try VaultFile.atomicWrite(blob: Data("second".utf8), to: target)

        let read = try Data(contentsOf: target)
        #expect(read == Data("second".utf8))
    }
}
