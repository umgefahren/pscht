import ArgumentParser

struct RemoveCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a key or all keys in a namespace"
    )

    @Argument(help: "The namespace")
    var namespace: String

    @Argument(help: "Optional key to remove (removes all keys if omitted)")
    var key: String?

    mutating func run() throws {
        if let key {
            try Keychain.delete(namespace: namespace, key: key)
        } else {
            print("Remove all keys in namespace '\(namespace)'? [y/N] ", terminator: "")
            guard let answer = readLine(), answer.lowercased() == "y" else {
                throw CleanExit.message("Aborted")
            }
            try Keychain.deleteAll(namespace: namespace)
        }
    }
}
