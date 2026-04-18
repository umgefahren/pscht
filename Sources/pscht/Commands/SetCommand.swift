import ArgumentParser
import Darwin

struct SetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "set",
        abstract: "Store secrets in a namespace"
    )

    @OptionGroup var bio: BiometricOptions

    @Argument(help: "The namespace to store secrets in")
    var namespace: String

    @Argument(help: "One or more key names to set")
    var keys: [String]

    mutating func run() async throws {
        var pairs: [(String, String)] = []
        for key in keys {
            let prompt = "\(key): "
            var buf = [CChar](repeating: 0, count: 1024)
            guard let cstr = readpassphrase(prompt, &buf, buf.count, 0) else {
                throw CleanExit.message("Failed to read value for \(key)")
            }
            let value = String(cString: cstr)
            buf.withUnsafeMutableBufferPointer { ptr in
                ptr.update(repeating: 0)
            }

            guard !value.isEmpty else {
                throw CleanExit.message("Empty value for \(key), skipping")
            }
            pairs.append((key, value))
        }

        let existing = Set(try Keychain.listKeys(namespace: namespace))
        let overwriting = keys.filter { existing.contains($0) }

        let overwriteContext = try await overwriting.isEmpty
            ? nil
            : Keychain.authContext(
                reason: "overwrite \(overwriting.count) existing secret(s) in '\(namespace)'"
            )

        for (key, value) in pairs {
            let ctx = existing.contains(key) ? overwriteContext : nil
            try Keychain.store(
                namespace: namespace,
                key: key,
                value: value,
                biometricProtected: !bio.noBio,
                overwriteContext: ctx
            )
        }
    }
}
