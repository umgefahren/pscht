import ArgumentParser

struct GetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Retrieve a single secret"
    )

    @Argument(help: "The namespace")
    var namespace: String

    @Argument(help: "The key to retrieve")
    var key: String

    mutating func run() async throws {
        let store = CommandContext.shared.store
        let session = try await store.beginSession(reason: "read '\(key)' from '\(namespace)'")
        let value = try await store.retrieve(namespace: namespace, key: key, session: session)
        print(value, terminator: "")
    }
}
