import ArgumentParser

struct GetCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Retrieve a single secret"
    )

    @OptionGroup var bio: BiometricOptions

    @Argument(help: "The namespace")
    var namespace: String

    @Argument(help: "The key to retrieve")
    var key: String

    mutating func run() throws {
        try bio.authenticateIfNeeded(reason: "read '\(key)' from '\(namespace)'")
        let value = try Keychain.retrieve(namespace: namespace, key: key)
        print(value, terminator: "")
    }
}
