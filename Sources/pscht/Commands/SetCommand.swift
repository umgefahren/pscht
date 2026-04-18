import ArgumentParser
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct SetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "set",
        abstract: "Store secrets in a namespace"
    )

    #if os(macOS)
    @OptionGroup var bio: BiometricOptions
    #endif

    @Argument(help: "The namespace to store secrets in")
    var namespace: String

    @Argument(help: "One or more key names to set")
    var keys: [String]

    mutating func run() async throws {
        var pairs: [(String, String)] = []
        for key in keys {
            let prompt = "\(key): "
            let value = try readSecretLine(prompt: prompt, key: key)
            guard !value.isEmpty else {
                throw CleanExit.message("Empty value for \(key), skipping")
            }
            pairs.append((key, value))
        }

        let store = CommandContext.shared.store
        let existing = Set(try await store.listKeys(namespace: namespace))
        let overwriting = keys.filter { existing.contains($0) }

        let session: (any SecretStoreSession)?
        #if os(macOS)
        // macOS: only prompt for Touch ID when overwriting a biometric-
        // protected item. Fresh inserts don't require auth.
        if overwriting.isEmpty {
            session = nil
        } else {
            session = try await store.beginSession(
                reason: "overwrite \(overwriting.count) existing secret(s) in '\(namespace)'"
            )
        }
        #else
        // Linux: every write requires the vault to be unsealed.
        session = try await store.beginSession(
            reason: overwriting.isEmpty
                ? "write \(keys.count) secret(s) to '\(namespace)'"
                : "overwrite \(overwriting.count) existing secret(s) in '\(namespace)'"
        )
        #endif

        #if os(macOS)
        let options = StoreOptions(biometricProtected: !bio.noBio)
        #else
        let options = StoreOptions()
        #endif

        for (key, value) in pairs {
            #if os(macOS)
            // Only pass a session when overwriting a biometric-protected item.
            let sess = existing.contains(key) ? session : nil
            #else
            // Linux: always pass the session; writes require the unsealed vault.
            let sess = session
            #endif
            try await store.store(
                namespace: namespace,
                key: key,
                value: value,
                options: options,
                session: sess
            )
        }
    }

    /// Read a line from the terminal with echo disabled.
    /// On macOS this uses BSD `readpassphrase`; on Linux, `getpass`.
    private func readSecretLine(prompt: String, key: String) throws -> String {
        #if os(macOS)
        return try withUnsafeTemporaryAllocation(of: CChar.self, capacity: 1024) { buf -> String in
            defer { buf.update(repeating: 0) }
            guard let base = buf.baseAddress,
                  let cstr = readpassphrase(prompt, base, buf.count, 0) else {
                throw CleanExit.message("Failed to read value for \(key)")
            }
            return String(cString: cstr)
        }
        #elseif os(Linux)
        // getpass is deprecated but ubiquitous; a real tty-aware replacement
        // lands when the Linux backend ships. For now it lets the refactor compile.
        guard let cstr = getpass(prompt) else {
            throw CleanExit.message("Failed to read value for \(key)")
        }
        return String(cString: cstr)
        #else
        throw CleanExit.message("Unsupported platform")
        #endif
    }
}
