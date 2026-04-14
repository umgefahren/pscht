import ArgumentParser

struct GetCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Retrieve a single secret"
    )

    @Argument(help: "The namespace")
    var namespace: String

    @Argument(help: "The key to retrieve")
    var key: String

    mutating func run() throws {
        let context = try Keychain.authContext(reason: "read '\(key)' from '\(namespace)'")
        let value = try Keychain.retrieve(namespace: namespace, key: key, context: context)
        print(value, terminator: "")
    }
}
