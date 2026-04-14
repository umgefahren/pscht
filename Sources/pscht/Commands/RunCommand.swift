import ArgumentParser
import Foundation
import Subprocess

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run a command with secrets as environment variables"
    )

    @Argument(help: "Comma-separated namespace(s)")
    var namespaces: String

    @Argument(parsing: .captureForPassthrough, help: "Command and arguments to run")
    var command: [String]

    mutating func run() async throws {
        guard !command.isEmpty else {
            throw CleanExit.message("No command specified")
        }

        let nsList = namespaces.split(separator: ",").map(String.init)

        let context = try Keychain.authContext(
            reason: "run with secrets from \(nsList.joined(separator: ", "))"
        )

        var envOverrides: [Environment.Key: String?] = [:]

        for ns in nsList {
            let pairs = try Keychain.retrieveAll(namespace: ns, context: context)
            for (key, value) in pairs {
                envOverrides[Environment.Key(stringLiteral: key)] = value
            }
        }

        let args = Arguments(command.dropFirst().map { String($0) })

        let result = try await Subprocess.run(
            .name(command[0]),
            arguments: args,
            environment: .inherit.updating(envOverrides),
            input: .fileDescriptor(.standardInput, closeAfterSpawningProcess: false),
            output: .standardOutput,
            error: .standardError
        )

        switch result.terminationStatus {
        case .exited(let code):
            throw ExitCode(code)
        case .signaled(let signal):
            throw ExitCode(128 + signal)
        }
    }
}
