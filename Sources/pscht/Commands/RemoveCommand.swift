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
        if let key {
            let context = try await Keychain.authContext(
                reason: "delete '\(key)' from '\(namespace)'"
            )
            try Keychain.delete(namespace: namespace, key: key, context: context)
        } else {
            print("Remove all keys in namespace '\(namespace)'? [y/N] ", terminator: "")
            guard let answer = readLine(), answer.lowercased() == "y" else {
                throw CleanExit.message("Aborted")
            }
            let context = try await Keychain.authContext(
                reason: "delete all secrets in '\(namespace)'"
            )
            try Keychain.deleteAll(namespace: namespace, context: context)
        }
    }
}
