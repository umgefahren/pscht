import ArgumentParser

@main
struct Pscht: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pscht",
        abstract: "Store secrets in macOS Keychain with biometric protection",
        subcommands: [
            SetCommand.self,
            GetCommand.self,
            RunCommand.self,
            ListCommand.self,
            RemoveCommand.self,
            MigrateCommand.self,
        ]
    )
}
