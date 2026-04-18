#if os(Linux)
import Foundation
import Crypto
import Glibc

/// Linux TPM2-backed `SecretStore`.
///
/// Layout under `config.effectiveDataDir`:
/// - `sealed.ctx` — TPM2 sealed object (holds the random 32-byte key `K_t`).
/// - `vault.enc` — ChaCha20-Poly1305(vault JSON). AEAD key derived from
///   `K_t` + Argon2id(PIN) via HKDF-SHA256.
/// - `index.json` — cleartext list of namespaces and key names for fast
///   completion without unsealing.
///
/// Writes are eager: every mutation re-encrypts `vault.enc` and rewrites
/// `index.json` atomically. A CLI invocation typically only performs one
/// mutation, so this keeps the session model simple at a small CPU cost.
final class TPM2VaultStore: SecretStore, @unchecked Sendable {
    let config: PschtConfig

    init(config: PschtConfig) {
        self.config = config
    }

    private var dataDir: URL { config.effectiveDataDir }
    private var sealedContextPath: URL { dataDir.appendingPathComponent("sealed.ctx") }
    private var vaultPath: URL { dataDir.appendingPathComponent("vault.enc") }
    private var indexPath: URL { dataDir.appendingPathComponent("index.json") }

    // MARK: - Session

    /// Reference-type session so mutations made through one `store()` call
    /// are visible to subsequent calls (e.g. `pscht set ns a b c`).
    final class Session: SecretStoreSession, @unchecked Sendable {
        var vault: VaultState
        let masterKey: SymmetricKey
        let storeRef: TPM2VaultStore

        init(vault: VaultState, masterKey: SymmetricKey, store: TPM2VaultStore) {
            self.vault = vault
            self.masterKey = masterKey
            self.storeRef = store
        }
    }

    // MARK: - SecretStore conformance

    func beginSession(reason: String) async throws -> any SecretStoreSession {
        guard FileManager.default.fileExists(atPath: sealedContextPath.path) else {
            throw SecretStoreError.vaultMissing
        }
        guard FileManager.default.fileExists(atPath: vaultPath.path) else {
            throw SecretStoreError.vaultMissing
        }

        let pin = try promptForPinIfNeeded(reason: reason)
        let masterKey = try await deriveMasterKey(pin: pin)

        let blob: Data
        do {
            blob = try Data(contentsOf: vaultPath)
        } catch {
            throw SecretStoreError.vaultCorrupt("reading vault.enc: \(error.localizedDescription)")
        }
        let (plaintext, _) = try VaultFile.open(blob: blob, key: masterKey)

        let vault: VaultState
        do {
            vault = try JSONDecoder().decode(VaultState.self, from: plaintext)
        } catch {
            throw SecretStoreError.vaultCorrupt("vault JSON: \(error.localizedDescription)")
        }

        return Session(vault: vault, masterKey: masterKey, store: self)
    }

    func store(
        namespace: String,
        key: String,
        value: String,
        options: StoreOptions,
        session: (any SecretStoreSession)?
    ) async throws {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("store")
        }
        s.vault.set(namespace: namespace, key: key, value: value)
        try persist(session: s)
    }

    func retrieve(namespace: String, key: String, session: any SecretStoreSession) async throws -> String {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("retrieve")
        }
        guard let value = s.vault.get(namespace: namespace, key: key) else {
            throw SecretStoreError.notFound(namespace: namespace, key: key)
        }
        return value
    }

    func retrieveAll(namespace: String, session: any SecretStoreSession) async throws -> [(String, String)] {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("retrieveAll")
        }
        return s.vault.all(namespace: namespace)
    }

    func delete(namespace: String, key: String, session: any SecretStoreSession) async throws {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("delete")
        }
        s.vault.delete(namespace: namespace, key: key)
        try persist(session: s)
    }

    func deleteAll(namespace: String, session: any SecretStoreSession) async throws {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("deleteAll")
        }
        s.vault.deleteAll(namespace: namespace)
        try persist(session: s)
    }

    func listKeys(namespace: String) async throws -> [String] {
        let index = try readIndexIfPresent()
        return (index?.keys[namespace] ?? []).sorted()
    }

    func listNamespaces() async throws -> [String] {
        let index = try readIndexIfPresent()
        return (index?.namespaces ?? []).sorted()
    }

    // MARK: - Init / Rekey

    /// Create the vault from scratch. Seals a fresh 32-byte key into the TPM
    /// under `pin` (if provided), then writes an empty encrypted vault.
    func initializeVault(pin: String?) async throws {
        if FileManager.default.fileExists(atPath: sealedContextPath.path) ||
           FileManager.default.fileExists(atPath: vaultPath.path) {
            throw SecretStoreError.atomicWriteFailed(
                "Vault already exists at \(dataDir.path); refusing to overwrite"
            )
        }
        try FileManager.default.createDirectory(
            at: dataDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        // Seal a fresh 32-byte random key into the TPM.
        var kt = SecretBytes(count: 32)
        try kt.withMutableBytes { buf throws(SecretStoreError) in
            for i in 0..<buf.count {
                buf[i] = UInt8.random(in: 0...255)
            }
        }

        try await TPM2Tools.seal(
            key: kt,
            pin: pin,
            config: TPM2Tools.Config(device: config.tpm2.device),
            sealedContextPath: sealedContextPath
        )

        // Derive master key and write an empty vault.
        let masterKey = try deriveMasterKey(kt: kt, pin: pin)
        let emptyVault = VaultState()
        try writeVault(emptyVault, masterKey: masterKey)
    }

    /// Rotate the sealed master key and re-encrypt the vault. Writes
    /// `sealed.ctx.new` and `vault.enc.new`, then moves each into place,
    /// preserving `.backup` copies so the user can recover manually if the
    /// process is interrupted mid-swap.
    func rekey(session: Session, newPin: String?) async throws {
        let newSealedPath = sealedContextPath.appendingPathExtension("new")
        let newVaultPath = vaultPath.appendingPathExtension("new")
        let sealedBackup = sealedContextPath.appendingPathExtension("backup")
        let vaultBackup = vaultPath.appendingPathExtension("backup")

        // Clean up any leftovers from an interrupted previous rekey.
        try? FileManager.default.removeItem(at: newSealedPath)
        try? FileManager.default.removeItem(at: newVaultPath)

        // 1. Generate new K_t and seal it with the new PIN.
        var newKt = SecretBytes(count: 32)
        try newKt.withMutableBytes { buf throws(SecretStoreError) in
            for i in 0..<buf.count {
                buf[i] = UInt8.random(in: 0...255)
            }
        }
        try await TPM2Tools.seal(
            key: newKt,
            pin: newPin,
            config: TPM2Tools.Config(device: config.tpm2.device),
            sealedContextPath: newSealedPath
        )

        // 2. Re-encrypt the (already-decrypted) vault with the new master key.
        let newMaster = try deriveMasterKey(kt: newKt, pin: newPin)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plaintext: Data
        do {
            plaintext = try encoder.encode(session.vault)
        } catch {
            throw SecretStoreError.storeFailed("encode vault: \(error.localizedDescription)")
        }
        let indexBytes: Data
        do {
            indexBytes = try encoder.encode(session.vault.buildIndex())
        } catch {
            throw SecretStoreError.storeFailed("encode index: \(error.localizedDescription)")
        }
        let indexHash = Data(SHA256.hash(data: indexBytes))
        let blob = try VaultFile.seal(plaintext: plaintext, key: newMaster, indexHash: indexHash)
        try VaultFile.atomicWrite(blob: blob, to: newVaultPath)

        // 3. Commit: rename old → .backup, then .new → real, for each file.
        try swapInPlace(from: sealedContextPath, to: sealedBackup)
        try swapInPlace(from: newSealedPath, to: sealedContextPath)
        try swapInPlace(from: vaultPath, to: vaultBackup)
        try swapInPlace(from: newVaultPath, to: vaultPath)

        // Index.json needs to reflect the new vault too; rewrite it.
        try VaultFile.atomicWrite(blob: indexBytes, to: indexPath)

        // 4. Remove backups once both swaps succeeded.
        try? FileManager.default.removeItem(at: sealedBackup)
        try? FileManager.default.removeItem(at: vaultBackup)
    }

    private func swapInPlace(from src: URL, to dst: URL) throws {
        // Raw rename(2) — replaces dst atomically if it exists.
        let rc = src.path.withCString { s in
            dst.path.withCString { d in rename(s, d) }
        }
        if rc != 0 {
            let err = String(cString: strerror(errno))
            throw SecretStoreError.atomicWriteFailed("rename \(src.path) → \(dst.path): \(err)")
        }
    }

    // MARK: - Persistence

    fileprivate func persist(session s: Session) throws {
        try writeVault(s.vault, masterKey: s.masterKey)
    }

    private func writeVault(_ vault: VaultState, masterKey: SymmetricKey) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plaintext: Data
        do {
            plaintext = try encoder.encode(vault)
        } catch {
            throw SecretStoreError.storeFailed("encode vault: \(error.localizedDescription)")
        }

        let index = vault.buildIndex()
        let indexBytes: Data
        do {
            indexBytes = try encoder.encode(index)
        } catch {
            throw SecretStoreError.storeFailed("encode index: \(error.localizedDescription)")
        }
        let indexHash = Data(SHA256.hash(data: indexBytes))

        let blob = try VaultFile.seal(
            plaintext: plaintext,
            key: masterKey,
            indexHash: indexHash
        )

        // Order: vault first (the source of truth) then index. A crash between
        // the two leaves the index stale; we detect+rebuild on next open.
        try VaultFile.atomicWrite(blob: blob, to: vaultPath)
        try VaultFile.atomicWrite(blob: indexBytes, to: indexPath)
    }

    private func readIndexIfPresent() throws -> VaultIndex? {
        guard FileManager.default.fileExists(atPath: indexPath.path) else {
            return nil
        }
        let data: Data
        do {
            data = try Data(contentsOf: indexPath)
        } catch {
            return nil
        }
        return try? JSONDecoder().decode(VaultIndex.self, from: data)
    }

    // MARK: - Key derivation

    /// Derive the master vault key. Unseals `K_t` from the TPM and combines
    /// it with Argon2id(PIN) via HKDF-SHA256. In presence mode (no PIN), the
    /// Argon2 step is skipped and `K_p` is 32 zeros.
    private func deriveMasterKey(pin: String?) async throws -> SymmetricKey {
        let kt = try await TPM2Tools.unseal(
            sealedContextPath: sealedContextPath,
            pin: pin,
            config: TPM2Tools.Config(device: config.tpm2.device)
        )
        return try deriveMasterKey(kt: kt, pin: pin)
    }

    private func deriveMasterKey(kt: borrowing SecretBytes, pin: String?) throws -> SymmetricKey {
        // K_p = Argon2id(pin || salt) if PIN mode, else 32 zero bytes.
        let kpBytes: Data
        if let pin, !pin.isEmpty {
            let salt = makeArgon2Salt()
            let kpSecret = try Argon2.hash(
                password: Data(pin.utf8),
                salt: salt,
                params: .init(
                    memoryKiB: UInt32(config.tpm2.argon2.memoryKiB),
                    iterations: UInt32(config.tpm2.argon2.iterations),
                    parallelism: UInt32(config.tpm2.argon2.parallelism)
                )
            )
            kpBytes = kpSecret.withBytes { buf in
                Data(bytes: buf.baseAddress!, count: buf.count)
            }
        } else {
            kpBytes = Data(repeating: 0, count: 32)
        }

        // IKM = K_t || K_p
        var ikm = Data()
        kt.withBytes { buf in
            ikm.append(contentsOf: UnsafeRawBufferPointer(buf))
        }
        ikm.append(kpBytes)

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: Data("pscht-vault-salt-v1".utf8),
            info: Data("pscht-vault-v1".utf8),
            outputByteCount: 32
        )

        // Best-effort wipe of the intermediate IKM bytes.
        let _: Void = ikm.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) in
            ptr.initializeMemory(as: UInt8.self, repeating: 0)
        }

        return derived
    }

    /// Stable per-host salt: SHA-256("pscht/pin-salt/v1" || /etc/machine-id).
    /// Falls back to a fixed salt if /etc/machine-id is absent (unusual, but
    /// we still want a functional derivation).
    private func makeArgon2Salt() -> Data {
        let tag = Data("pscht/pin-salt/v1".utf8)
        var input = tag
        if let mid = try? String(contentsOfFile: "/etc/machine-id", encoding: .utf8) {
            input.append(Data(mid.trimmingCharacters(in: .whitespacesAndNewlines).utf8))
        }
        return Data(SHA256.hash(data: input))
    }

    // MARK: - Testing hooks

    /// Test-only: run the unlock path with a known PIN, bypassing getpass.
    /// Exposed via `@testable import pscht` from the integration tests.
    internal func beginSessionForTesting(pin: String?) async throws -> any SecretStoreSession {
        guard FileManager.default.fileExists(atPath: sealedContextPath.path) else {
            throw SecretStoreError.vaultMissing
        }
        guard FileManager.default.fileExists(atPath: vaultPath.path) else {
            throw SecretStoreError.vaultMissing
        }
        let masterKey = try await deriveMasterKey(pin: pin)
        let blob: Data
        do {
            blob = try Data(contentsOf: vaultPath)
        } catch {
            throw SecretStoreError.vaultCorrupt("reading vault.enc: \(error.localizedDescription)")
        }
        let (plaintext, _) = try VaultFile.open(blob: blob, key: masterKey)
        let vault: VaultState
        do {
            vault = try JSONDecoder().decode(VaultState.self, from: plaintext)
        } catch {
            throw SecretStoreError.vaultCorrupt("vault JSON: \(error.localizedDescription)")
        }
        return Session(vault: vault, masterKey: masterKey, store: self)
    }

    // MARK: - PIN prompt

    private func promptForPinIfNeeded(reason: String) throws -> String? {
        guard config.tpm2.mode == .pin else {
            return nil
        }
        // tty-based getpass for now; systemd-ask-password support can layer
        // on later via config.tpm2.pinPrompt == .systemd.
        let prompt = "pscht: \(reason)\nPIN: "
        guard let cstr = getpass(prompt) else {
            throw SecretStoreError.authCancelled
        }
        let pin = String(cString: cstr)
        if pin.isEmpty {
            throw SecretStoreError.authCancelled
        }
        return pin
    }
}

// MARK: - Vault state + index

struct VaultState: Codable, Sendable {
    var version: Int = 1
    var namespaces: [String: [String: String]] = [:]

    mutating func set(namespace: String, key: String, value: String) {
        var ns = namespaces[namespace] ?? [:]
        ns[key] = value
        namespaces[namespace] = ns
    }

    func get(namespace: String, key: String) -> String? {
        namespaces[namespace]?[key]
    }

    func all(namespace: String) -> [(String, String)] {
        guard let ns = namespaces[namespace] else { return [] }
        return ns.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    mutating func delete(namespace: String, key: String) {
        namespaces[namespace]?[key] = nil
        if namespaces[namespace]?.isEmpty == true {
            namespaces[namespace] = nil
        }
    }

    mutating func deleteAll(namespace: String) {
        namespaces[namespace] = nil
    }

    func buildIndex() -> VaultIndex {
        var keys: [String: [String]] = [:]
        for (ns, pairs) in namespaces {
            keys[ns] = pairs.keys.sorted()
        }
        return VaultIndex(namespaces: namespaces.keys.sorted(), keys: keys)
    }
}

struct VaultIndex: Codable, Sendable {
    var namespaces: [String]
    var keys: [String: [String]]
}
#endif
