import ArgumentParser

struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List namespaces or keys within a namespace"
    )

    @Argument(help: "Optional namespace to list keys for")
    var namespace: String?

    mutating func run() async throws {
        let store = CommandContext.shared.store
        if let namespace {
            let keys = try await store.listKeys(namespace: namespace)
            for key in keys {
                print(key)
            }
        } else {
            let namespaces = try await store.listNamespaces()
            for ns in namespaces {
                print(ns)
            }
        }
    }
}
