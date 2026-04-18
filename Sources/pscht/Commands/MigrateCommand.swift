#if os(macOS)
import ArgumentParser

struct MigrateCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "migrate",
        abstract: "Re-store all secrets with biometric (Keychain ACL) protection"
    )

    @OptionGroup var timingOpts: TimingOptions

    mutating func run() throws {
        timingOpts.apply()
        defer { Timings.shared.report() }
        let store = KeychainStore()
        let namespaces = try store.listNamespacesSync(useDataProtection: false)

        guard !namespaces.isEmpty else {
            print("No namespaces found, nothing to migrate.")
            return
        }

        var total = 0
        for ns in namespaces {
            let keys = try store.listKeysSync(namespace: ns, useDataProtection: false)
            for key in keys {
                let value = try store.retrieveSync(
                    namespace: ns,
                    key: key,
                    useDataProtection: false
                )
                try store.storeSync(
                    namespace: ns,
                    key: key,
                    value: value,
                    biometricProtected: true
                )
                total += 1
            }
            print("Migrated \(ns): \(keys.count) key\(keys.count == 1 ? "" : "s")")
        }

        print("Done. \(total) secret\(total == 1 ? "" : "s") now protected with biometric ACL.")
    }
}
#endif
