import ArgumentParser

struct ListCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List namespaces or keys within a namespace"
    )

    @Argument(help: "Optional namespace to list keys for")
    var namespace: String?

    mutating func run() throws {
        if let namespace {
            let keys = try Keychain.listKeys(namespace: namespace)
            for key in keys {
                print(key)
            }
        } else {
            let namespaces = try Keychain.listNamespaces()
            for ns in namespaces {
                print(ns)
            }
        }
    }
}
