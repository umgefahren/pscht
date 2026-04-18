import ArgumentParser

@main
struct Pscht: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pscht",
        abstract: "Store secrets with biometric / TPM2 protection",
        subcommands: Self.subcommandsForPlatform
    )

    private static var subcommandsForPlatform: [any ParsableCommand.Type] {
        var cmds: [any ParsableCommand.Type] = [
            SetCommand.self,
            GetCommand.self,
            RunCommand.self,
            ListCommand.self,
            RemoveCommand.self,
        ]
        #if os(macOS)
        cmds.append(MigrateCommand.self)
        #elseif os(Linux)
        cmds.append(InitCommand.self)
        cmds.append(RekeyCommand.self)
        #endif
        return cmds
    }
}
