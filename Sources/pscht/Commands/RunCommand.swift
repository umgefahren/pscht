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
        let store = CommandContext.shared.store

        let session = try await store.beginSession(
            reason: "run with secrets from \(nsList.joined(separator: ", "))"
        )

        var envOverrides: [Environment.Key: String?] = [:]

        for ns in nsList {
            let pairs = try await store.retrieveAll(namespace: ns, session: session)
            for (key, value) in pairs {
                envOverrides[Environment.Key(stringLiteral: key)] = value
            }
        }

        let resolved = resolveExecutable(command[0])
        FileHandle.standardError.write(Data("pscht: exec \(resolved)\n".utf8))

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

    /// Resolve `name` against PATH the way `execvp` would, so we can show the user
    /// exactly which binary is receiving their secrets. Returns the original name if
    /// it's already a path or can't be resolved (Subprocess will surface any error).
    private func resolveExecutable(_ name: String) -> String {
        if name.contains("/") {
            return name
        }
        guard let path = ProcessInfo.processInfo.environment["PATH"] else {
            return name
        }
        let fm = FileManager.default
        for dir in path.split(separator: ":", omittingEmptySubsequences: false) {
            let candidate = dir.isEmpty ? name : "\(dir)/\(name)"
            if fm.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        return name
    }
}
