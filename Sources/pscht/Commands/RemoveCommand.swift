import ArgumentParser

struct RemoveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a key or all keys in a namespace"
    )

    @Argument(help: "The namespace")
    var namespace: String

    @Argument(help: "Optional key to remove (removes all keys if omitted)")
    var key: String?

    mutating func run() async throws {
        let store = CommandContext.shared.store

        if let key {
            let session = try await store.beginSession(
                reason: "delete '\(key)' from '\(namespace)'"
            )
            try await store.delete(namespace: namespace, key: key, session: session)
        } else {
            print("Remove all keys in namespace '\(namespace)'? [y/N] ", terminator: "")
            guard let answer = readLine(), answer.lowercased() == "y" else {
                throw CleanExit.message("Aborted")
            }
            let session = try await store.beginSession(
                reason: "delete all secrets in '\(namespace)'"
            )
            try await store.deleteAll(namespace: namespace, session: session)
        }
    }
}
