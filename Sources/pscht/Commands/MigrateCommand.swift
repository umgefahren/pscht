import ArgumentParser

struct MigrateCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "migrate",
        abstract: "Re-store all secrets with biometric (Keychain ACL) protection"
    )

    mutating func run() throws {
        let namespaces = try Keychain.listNamespaces()

        guard !namespaces.isEmpty else {
            print("No namespaces found, nothing to migrate.")
            return
        }

        var total = 0
        for ns in namespaces {
            let keys = try Keychain.listKeys(namespace: ns)
            for key in keys {
                let value = try Keychain.retrieve(namespace: ns, key: key)
                try Keychain.store(namespace: ns, key: key, value: value, biometricProtected: true)
                total += 1
            }
            print("Migrated \(ns): \(keys.count) key\(keys.count == 1 ? "" : "s")")
        }

        print("Done. \(total) secret\(total == 1 ? "" : "s") now protected with biometric ACL.")
    }
}
