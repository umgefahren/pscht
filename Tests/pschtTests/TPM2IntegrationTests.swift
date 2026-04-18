#if os(Linux) && ENABLE_TPM_TESTS
import Testing
import Foundation
@testable import pscht

/// Integration tests that exercise TPM2VaultStore against a real (virtual)
/// TPM — either `/dev/tpmrm0` or a swtpm simulator. Gated behind
/// `ENABLE_TPM_TESTS` because they require external state (swtpm running
/// at the configured socket, or tpm2-tools on PATH with device access).
///
/// Run with:
///   swift test -Xswiftc -DENABLE_TPM_TESTS
///   (after `swtpm socket --tpm2 --tpmstate dir=/tmp/pscht-swtpm
///    --server type=unixio,path=/tmp/pscht-swtpm/sock
///    --ctrl type=unixio,path=/tmp/pscht-swtpm/sock.ctrl --daemon`)
@Suite(
    .enabled(if: FileManager.default.fileExists(atPath: "/tmp/pscht-swtpm/sock")),
    .serialized
)
struct TPM2IntegrationTests {
    private func makeStore(mode: PschtConfig.Tpm2Mode) -> (TPM2VaultStore, URL) {
        let dataDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pscht-tpm-test-\(UUID().uuidString)")

        var cfg = PschtConfig()
        cfg.backend = .tpm2
        cfg.dataDir = dataDir.path
        cfg.tpm2.device = "swtpm:path=/tmp/pscht-swtpm/sock"
        cfg.tpm2.mode = mode
        // Keep Argon2 cheap so tests aren't painful.
        cfg.tpm2.argon2.memoryKiB = 4096
        cfg.tpm2.argon2.iterations = 1
        cfg.tpm2.argon2.parallelism = 1

        return (TPM2VaultStore(config: cfg), dataDir)
    }

    @Test("init → store → retrieve round-trip with PIN")
    func pinRoundTrip() async throws {
        let (store, dataDir) = makeStore(mode: .pin)
        defer { try? FileManager.default.removeItem(at: dataDir) }

        try await store.initializeVault(pin: "s3cret")

        let session = try await store.unlockWithPin(pin: "s3cret")
        try await store.store(
            namespace: "aws",
            key: "AWS_ACCESS_KEY_ID",
            value: "AKIAEXAMPLE",
            options: StoreOptions(),
            session: session
        )
        try await store.store(
            namespace: "aws",
            key: "AWS_SECRET_ACCESS_KEY",
            value: "topSecret",
            options: StoreOptions(),
            session: session
        )

        // Re-unlock simulates a fresh process; uses the same sealed.ctx.
        let session2 = try await store.unlockWithPin(pin: "s3cret")
        let k = try await store.retrieve(namespace: "aws", key: "AWS_ACCESS_KEY_ID", session: session2)
        let s = try await store.retrieve(namespace: "aws", key: "AWS_SECRET_ACCESS_KEY", session: session2)
        #expect(k == "AKIAEXAMPLE")
        #expect(s == "topSecret")

        let all = try await store.retrieveAll(namespace: "aws", session: session2)
        #expect(all.count == 2)

        // Index.json should exist and list the two keys.
        let keys = try await store.listKeys(namespace: "aws")
        #expect(keys == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])
        let namespaces = try await store.listNamespaces()
        #expect(namespaces == ["aws"])
    }

    @Test("Wrong PIN surfaces as authentication error")
    func wrongPin() async throws {
        let (store, dataDir) = makeStore(mode: .pin)
        defer { try? FileManager.default.removeItem(at: dataDir) }
        try await store.initializeVault(pin: "right")
        await #expect(throws: SecretStoreError.self) {
            _ = try await store.unlockWithPin(pin: "wrong")
        }
    }

    @Test("Presence mode unlocks without PIN")
    func presenceMode() async throws {
        let (store, dataDir) = makeStore(mode: .presence)
        defer { try? FileManager.default.removeItem(at: dataDir) }
        try await store.initializeVault(pin: nil)
        let session = try await store.unlockWithPin(pin: nil)
        try await store.store(
            namespace: "ns",
            key: "K",
            value: "V",
            options: StoreOptions(),
            session: session
        )
        let session2 = try await store.unlockWithPin(pin: nil)
        #expect(try await store.retrieve(namespace: "ns", key: "K", session: session2) == "V")
    }

    @Test("rekey rotates the master key and re-encrypts the vault")
    func rekey() async throws {
        let (store, dataDir) = makeStore(mode: .pin)
        defer { try? FileManager.default.removeItem(at: dataDir) }
        try await store.initializeVault(pin: "first")

        let s1 = try await store.unlockWithPin(pin: "first")
        try await store.store(
            namespace: "n",
            key: "k",
            value: "v",
            options: StoreOptions(),
            session: s1
        )

        guard let s1typed = s1 as? TPM2VaultStore.Session else {
            Issue.record("unexpected session type")
            return
        }
        try await store.rekey(session: s1typed, newPin: "second")

        // Old PIN must fail.
        await #expect(throws: SecretStoreError.self) {
            _ = try await store.unlockWithPin(pin: "first")
        }

        // New PIN opens the same data.
        let s2 = try await store.unlockWithPin(pin: "second")
        #expect(try await store.retrieve(namespace: "n", key: "k", session: s2) == "v")
    }
}

// Test-only helper that bypasses the interactive getpass prompt.
extension TPM2VaultStore {
    func unlockWithPin(pin: String?) async throws -> any SecretStoreSession {
        // Reach into beginSession logic but skip the prompt. Pull the private
        // derivation + read path by temporarily overriding via a custom entry
        // point — exposed via @testable.
        try await self.beginSessionForTesting(pin: pin)
    }
}
#endif
