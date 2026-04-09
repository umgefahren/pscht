import Foundation
import Security
import LocalAuthentication

enum KeychainError: Error, CustomStringConvertible {
    case storeFailed(OSStatus)
    case notFound(namespace: String, key: String)
    case authFailed(String)
    case unexpectedData
    case deleteFailed(OSStatus)
    case queryFailed(OSStatus)

    var description: String {
        switch self {
        case .storeFailed(let status):
            "Failed to store secret: \(SecCopyErrorMessageString(status, nil) ?? "OSStatus \(status)" as CFString)"
        case .notFound(let namespace, let key):
            "No secret found for '\(key)' in namespace '\(namespace)'"
        case .authFailed(let reason):
            "Authentication failed: \(reason)"
        case .unexpectedData:
            "Unexpected data format in keychain"
        case .deleteFailed(let status):
            "Failed to delete secret: \(SecCopyErrorMessageString(status, nil) ?? "OSStatus \(status)" as CFString)"
        case .queryFailed(let status):
            "Keychain query failed: \(SecCopyErrorMessageString(status, nil) ?? "OSStatus \(status)" as CFString)"
        }
    }
}

enum Keychain {
    private static let servicePrefix = "pscht."

    private static func serviceName(for namespace: String) -> String {
        "\(servicePrefix)\(namespace)"
    }

    /// Authenticate with Touch ID. Returns an authenticated LAContext.
    static func authenticate(reason: String = "access secrets") throws -> LAContext {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw KeychainError.authFailed(error?.localizedDescription ?? "Biometrics not available")
        }

        let semaphore = DispatchSemaphore(value: 0)
        var authError: NSError?

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "pscht: \(reason)"
        ) { success, evaluateError in
            if !success {
                authError = evaluateError as NSError?
            }
            semaphore.signal()
        }

        semaphore.wait()

        if let authError {
            throw KeychainError.authFailed(authError.localizedDescription)
        }

        return context
    }

    static func store(namespace: String, key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }

        let service = serviceName(for: namespace)

        // Delete existing item first (if any)
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeFailed(status)
        }
    }

    static func retrieve(namespace: String, key: String) throws -> String {
        let service = serviceName(for: namespace)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
                throw KeychainError.unexpectedData
            }
            return value
        case errSecItemNotFound:
            throw KeychainError.notFound(namespace: namespace, key: key)
        case errSecAuthFailed, errSecUserCanceled:
            throw KeychainError.authFailed("cancelled")
        default:
            throw KeychainError.queryFailed(status)
        }
    }

    static func delete(namespace: String, key: String) throws {
        let service = serviceName(for: namespace)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }

    static func deleteAll(namespace: String) throws {
        let service = serviceName(for: namespace)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }

    static func listKeys(namespace: String) throws -> [String] {
        let service = serviceName(for: namespace)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
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
            throw KeychainError.queryFailed(status)
        }
    }

    static func listNamespaces() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
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
                   service.hasPrefix(servicePrefix) {
                    namespaces.insert(String(service.dropFirst(servicePrefix.count)))
                }
            }
            return namespaces.sorted()
        case errSecItemNotFound:
            return []
        default:
            throw KeychainError.queryFailed(status)
        }
    }
}
