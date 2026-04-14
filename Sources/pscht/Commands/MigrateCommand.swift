import ArgumentParser

struct MigrateCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "migrate",
        abstract: "Re-store all secrets with biometric (Keychain ACL) protection"
    )

    mutating func run() throws {
        // Read from legacy keychain, write to data protection keychain
        let namespaces = try Keychain.listNamespaces(useDataProtection: false)

        guard !namespaces.isEmpty else {
            print("No namespaces found, nothing to migrate.")
            return
        }

        let context = try Keychain.authContext(reason: "migrate secrets")

        var total = 0
        for ns in namespaces {
            let keys = try Keychain.listKeys(namespace: ns, useDataProtection: false)
            for key in keys {
                let value = try Keychain.retrieve(namespace: ns, key: key, useDataProtection: false)
                try Keychain.store(namespace: ns, key: key, value: value, biometricProtected: true, context: context)
                total += 1
            }
            print("Migrated \(ns): \(keys.count) key\(keys.count == 1 ? "" : "s")")
        }

        print("Done. \(total) secret\(total == 1 ? "" : "s") now protected with biometric ACL.")
    }
}
