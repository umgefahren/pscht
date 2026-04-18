import ArgumentParser

struct GetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "get",
        abstract: "Retrieve a single secret"
    )

    @OptionGroup var timingOpts: TimingOptions

    @Argument(help: "The namespace")
    var namespace: String

    @Argument(help: "The key to retrieve")
    var key: String

    mutating func run() async throws {
        timingOpts.apply()
        defer { Timings.shared.report() }

        let store = CommandContext.shared.store
        // Don't wrap beginSession in Timings.measure — its inner steps
        // (PIN prompt, tpm2_unseal, Argon2, vault decrypt, JSON decode) are
        // already recorded individually, and wrapping would double-count.
        let session = try await store.beginSession(reason: "read '\(key)' from '\(namespace)'")
        let value = try await Timings.measure("retrieve") {
            try await store.retrieve(namespace: namespace, key: key, session: session)
        }
        print(value, terminator: "")
    }
}
