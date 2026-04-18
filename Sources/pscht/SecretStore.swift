import Foundation

/// Opaque pre-auth token cached for the duration of a single CLI invocation.
/// Backends carry platform-specific state here (LAContext on macOS, decrypted
/// vault on Linux). `run` calls `beginSession` once and reuses the session
/// across every namespace it retrieves.
protocol SecretStoreSession: Sendable {}

struct StoreOptions: Sendable {
    /// macOS: protect the item with a biometric ACL (`.biometryCurrentSet`).
    /// Linux: ignored — the whole vault is gated on TPM2+PIN.
    var biometricProtected: Bool = true
}

enum SecretStoreError: Error, CustomStringConvertible {
    case notFound(namespace: String, key: String)
    case alreadyExists(namespace: String, key: String)
    case authFailed(String)
    case authCancelled
    case unexpectedData
    case storeFailed(String)
    case queryFailed(String)
    case deleteFailed(String)
    case sessionRequired(String)

    case backendUnavailable(String)
    case tpmDeviceMissing(path: String)
    case tpmLockedOut(retryAfterSeconds: Int?)
    case pinIncorrect(attemptsRemaining: Int?)
    case vaultMissing
    case vaultCorrupt(String)
    case vaultVersionUnsupported(found: Int)
    case atomicWriteFailed(String)
    case configInvalid(String)
    case notImplemented(String)

    var description: String {
        switch self {
        case .notFound(let namespace, let key):
            "No secret found for '\(key)' in namespace '\(namespace)'"
        case .alreadyExists(let namespace, let key):
            "Secret '\(key)' already exists in namespace '\(namespace)' (overwrite requires re-authentication)"
        case .authFailed(let reason):
            "Authentication failed: \(reason)"
        case .authCancelled:
            "Authentication cancelled"
        case .unexpectedData:
            "Unexpected data format"
        case .storeFailed(let reason):
            "Failed to store secret: \(reason)"
        case .queryFailed(let reason):
            "Query failed: \(reason)"
        case .deleteFailed(let reason):
            "Failed to delete secret: \(reason)"
        case .sessionRequired(let operation):
            "\(operation) requires an authenticated session"
        case .backendUnavailable(let reason):
            "Secret store backend unavailable: \(reason)"
        case .tpmDeviceMissing(let path):
            "TPM2 device not available at \(path). Ensure your user is in the 'tss' group."
        case .tpmLockedOut(let retry):
            if let retry {
                "TPM2 is locked out after too many bad PINs. Retry in \(retry) seconds."
            } else {
                "TPM2 is locked out after too many bad PINs."
            }
        case .pinIncorrect(let remaining):
            if let remaining {
                "Incorrect PIN. \(remaining) attempt\(remaining == 1 ? "" : "s") remaining before lockout."
            } else {
                "Incorrect PIN."
            }
        case .vaultMissing:
            "Vault does not exist. Run `pscht init` to create one."
        case .vaultCorrupt(let detail):
            "Vault file is corrupt: \(detail)"
        case .vaultVersionUnsupported(let found):
            "Vault file version \(found) is not supported by this build of pscht"
        case .atomicWriteFailed(let detail):
            "Atomic vault write failed: \(detail)"
        case .configInvalid(let detail):
            "Invalid config: \(detail)"
        case .notImplemented(let what):
            "Not implemented: \(what)"
        }
    }
}

/// Cross-platform secret store abstraction.
///
/// `SessionIntent` is absent on purpose — on both platforms the backend does
/// the same work per unlock (one Touch ID, one TPM unseal), so there's nothing
/// to parameterize yet. Add it back if that changes.
protocol SecretStore: Sendable {
    /// Unlock the store. On macOS this runs the Touch ID sheet; on Linux it
    /// prompts for a PIN, unseals the TPM key, and decrypts the vault into
    /// the session's memory. Callers should hold the returned session for the
    /// rest of the command and let it go at the end.
    func beginSession(reason: String) async throws -> any SecretStoreSession

    /// Store `value`. If a key already exists under this namespace, the
    /// backend may require an authenticated `session` (macOS biometric ACL;
    /// Linux: always required for writes). Fresh writes on macOS accept
    /// `session == nil`.
    func store(
        namespace: String,
        key: String,
        value: String,
        options: StoreOptions,
        session: (any SecretStoreSession)?
    ) async throws

    func retrieve(namespace: String, key: String, session: any SecretStoreSession) async throws -> String
    func retrieveAll(namespace: String, session: any SecretStoreSession) async throws -> [(String, String)]
    func delete(namespace: String, key: String, session: any SecretStoreSession) async throws
    func deleteAll(namespace: String, session: any SecretStoreSession) async throws

    /// List operations never prompt. macOS runs a metadata-only query;
    /// Linux reads `index.json` without unsealing the vault.
    func listKeys(namespace: String) async throws -> [String]
    func listNamespaces() async throws -> [String]
}

/// Singleton context assembled at program start. Commands pull the concrete
/// store and config off `.shared` instead of taking them as parameters,
/// because swift-argument-parser's `ParsableCommand` initializers are
/// generated and can't receive dependency injection cleanly.
struct CommandContext: Sendable {
    let store: any SecretStore
    let config: PschtConfig

    static let shared: CommandContext = .makeDefault()

    private static func makeDefault() -> CommandContext {
        let config: PschtConfig
        do {
            config = try PschtConfigLoader.load()
        } catch {
            FileHandle.standardError.write(Data("pscht: \(error)\n".utf8))
            exit(78)  // EX_CONFIG
        }

        let store: any SecretStore
        switch config.effectiveBackend {
        case .keychain:
            #if os(macOS)
            store = KeychainStore()
            #else
            FileHandle.standardError.write(Data(
                "pscht: keychain backend is only available on macOS\n".utf8
            ))
            exit(78)
            #endif
        case .tpm2:
            #if os(Linux)
            store = TPM2VaultStore(config: config)
            #else
            FileHandle.standardError.write(Data(
                "pscht: tpm2 backend is only available on Linux\n".utf8
            ))
            exit(78)
            #endif
        case .auto:
            // effectiveBackend already resolved .auto; this is unreachable.
            fatalError("effectiveBackend returned .auto")
        }

        return CommandContext(store: store, config: config)
    }
}
