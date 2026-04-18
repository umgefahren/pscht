#if os(macOS)
import Foundation
import Security
@preconcurrency import LocalAuthentication

/// macOS Keychain-backed SecretStore.
///
/// Secrets are stored as `kSecClassGenericPassword` items with service
/// `pscht.<namespace>` and account = key. Biometric protection is
/// enforced by the OS via `SecAccessControl` with `.biometryCurrentSet`
/// — pscht itself is never trusted to gate access.
struct KeychainStore: SecretStore {
    private static let servicePrefix = "pscht."

    private func serviceName(for namespace: String) -> String {
        "\(Self.servicePrefix)\(namespace)"
    }

    /// The session is just the authenticated `LAContext`. Subsequent
    /// keychain queries that pass it via `kSecUseAuthenticationContext`
    /// satisfy biometric ACLs without re-prompting.
    struct Session: SecretStoreSession {
        let context: LAContext
    }

    func beginSession(reason: String) async throws -> any SecretStoreSession {
        try await Session(context: authContext(reason: reason))
    }

    /// Pre-authenticate with Touch ID. If the surrounding Task is cancelled
    /// (Ctrl+C while the sheet is up), invalidate the context so the sheet
    /// dismisses and `evaluatePolicy` resolves.
    private func authContext(reason: String) async throws(SecretStoreError) -> LAContext {
        let context = LAContext()

        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw .authFailed(error?.localizedDescription ?? "Biometrics not available")
        }

        do {
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    context.evaluatePolicy(
                        .deviceOwnerAuthenticationWithBiometrics,
                        localizedReason: "pscht: \(reason)"
                    ) { success, evaluateError in
                        if success {
                            continuation.resume(returning: context)
                        } else {
                            let message = (evaluateError as NSError?)?.localizedDescription ?? "authentication failed"
                            continuation.resume(throwing: SecretStoreError.authFailed(message))
                        }
                    }
                }
            } onCancel: {
                context.invalidate()
            }
        } catch let error as SecretStoreError {
            throw error
        } catch {
            throw .authFailed(error.localizedDescription)
        }
    }

    func store(
        namespace: String,
        key: String,
        value: String,
        options: StoreOptions,
        session: (any SecretStoreSession)?
    ) async throws {
        try storeSync(
            namespace: namespace,
            key: key,
            value: value,
            biometricProtected: options.biometricProtected,
            overwriteContext: (session as? Session)?.context
        )
    }

    /// Store a new secret, or overwrite an existing one if an authenticated
    /// context is provided. Overwriting a biometric-protected item without
    /// a pre-auth'd context would be a silent ACL bypass (SecItemDelete
    /// does not consult the ACL on macOS), so callers must demonstrate user
    /// presence by passing one.
    func storeSync(
        namespace: String,
        key: String,
        value: String,
        biometricProtected: Bool = true,
        overwriteContext: LAContext? = nil
    ) throws(SecretStoreError) {
        guard let data = value.data(using: .utf8) else {
            throw .unexpectedData
        }

        let service = serviceName(for: namespace)

        if let overwriteContext {
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key,
                kSecUseDataProtectionKeychain as String: true,
                kSecUseAuthenticationContext as String: overwriteContext,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
        }

        var addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
        ]

        if biometricProtected {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryCurrentSet,
                &error
            ) else {
                throw .storeFailed(Self.describe(errSecParam))
            }
            addQuery[kSecAttrAccessControl as String] = access
        } else {
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            addQuery[kSecUseDataProtectionKeychain as String] = true
        }

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw .alreadyExists(namespace: namespace, key: key)
        default:
            throw .storeFailed(Self.describe(status))
        }
    }

    func retrieve(namespace: String, key: String, session: any SecretStoreSession) async throws -> String {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("retrieve")
        }
        return try retrieveSync(namespace: namespace, key: key, context: s.context)
    }

    func retrieveSync(
        namespace: String,
        key: String,
        context: LAContext? = nil,
        useDataProtection: Bool = true
    ) throws(SecretStoreError) -> String {
        let service = serviceName(for: namespace)

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: useDataProtection,
        ]

        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
                throw .unexpectedData
            }
            return value
        case errSecItemNotFound:
            throw .notFound(namespace: namespace, key: key)
        case errSecAuthFailed:
            throw .authFailed("authentication failed")
        case errSecUserCanceled:
            throw .authCancelled
        case errSecInteractionNotAllowed:
            throw .authFailed("interaction not allowed")
        default:
            throw .queryFailed(Self.describe(status))
        }
    }

    func retrieveAll(namespace: String, session: any SecretStoreSession) async throws -> [(String, String)] {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("retrieveAll")
        }
        let service = serviceName(for: namespace)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: s.context,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else {
                return []
            }
            return items.compactMap { item in
                guard let account = item[kSecAttrAccount as String] as? String,
                      let data = item[kSecValueData as String] as? Data,
                      let value = String(data: data, encoding: .utf8) else {
                    return nil
                }
                return (account, value)
            }
        case errSecItemNotFound:
            return []
        case errSecAuthFailed:
            throw SecretStoreError.authFailed("authentication failed")
        case errSecUserCanceled:
            throw SecretStoreError.authCancelled
        case errSecInteractionNotAllowed:
            throw SecretStoreError.authFailed("interaction not allowed")
        default:
            throw SecretStoreError.queryFailed(Self.describe(status))
        }
    }

    func delete(namespace: String, key: String, session: any SecretStoreSession) async throws {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("delete")
        }
        let service = serviceName(for: namespace)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: s.context,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStoreError.deleteFailed(Self.describe(status))
        }
    }

    func deleteAll(namespace: String, session: any SecretStoreSession) async throws {
        guard let s = session as? Session else {
            throw SecretStoreError.sessionRequired("deleteAll")
        }
        let service = serviceName(for: namespace)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: s.context,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStoreError.deleteFailed(Self.describe(status))
        }
    }

    func listKeys(namespace: String) async throws -> [String] {
        try listKeysSync(namespace: namespace)
    }

    func listKeysSync(namespace: String, useDataProtection: Bool = true) throws(SecretStoreError) -> [String] {
        let service = serviceName(for: namespace)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecUseDataProtectionKeychain as String: useDataProtection,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else {
                return []
            }
            return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
        case errSecItemNotFound:
            return []
        default:
            throw .queryFailed(Self.describe(status))
        }
    }

    func listNamespaces() async throws -> [String] {
        try listNamespacesSync()
    }

    func listNamespacesSync(useDataProtection: Bool = true) throws(SecretStoreError) -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecUseDataProtectionKeychain as String: useDataProtection,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else {
                return []
            }
            var namespaces = Set<String>()
            for item in items {
                if let service = item[kSecAttrService as String] as? String,
                   service.hasPrefix(Self.servicePrefix) {
                    namespaces.insert(String(service.dropFirst(Self.servicePrefix.count)))
                }
            }
            return namespaces.sorted()
        case errSecItemNotFound:
            return []
        default:
            throw .queryFailed(Self.describe(status))
        }
    }

    /// Turn an OSStatus into a human-readable string via SecCopyErrorMessageString.
    private static func describe(_ status: OSStatus) -> String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
    }
}
#endif
