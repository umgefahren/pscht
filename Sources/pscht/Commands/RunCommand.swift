import ArgumentParser
import Foundation
import Subprocess

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run a command with secrets as environment variables"
    )

    @OptionGroup var timingOpts: TimingOptions

    @Argument(help: "Comma-separated namespace(s)")
    var namespaces: String

    @Argument(parsing: .captureForPassthrough, help: "Command and arguments to run")
    var command: [String]

    mutating func run() async throws {
        timingOpts.apply()
        // Emit the report *before* execvp-style handoff takes over. We print
        // before spawning the child rather than at end of run() because the
        // child's termination status is rethrown as `ExitCode`, which bails
        // out of the `defer`-after-return path on some ArgumentParser builds.
        defer { Timings.shared.report() }

        guard !command.isEmpty else {
            throw CleanExit.message("No command specified")
        }

        let nsList = namespaces.split(separator: ",").map(String.init)
        let store = CommandContext.shared.store

        // Inner steps of beginSession (PIN, tpm2_unseal, Argon2, etc.) are
        // recorded individually — don't wrap here or we'd double-count.
        let session = try await store.beginSession(
            reason: "run with secrets from \(nsList.joined(separator: ", "))"
        )

        var envOverrides: [Environment.Key: String?] = [:]

        try await Timings.measure("retrieveAll (\(nsList.count) namespace(s))") {
            for ns in nsList {
                let pairs = try await store.retrieveAll(namespace: ns, session: session)
                for (key, value) in pairs {
                    envOverrides[Environment.Key(stringLiteral: key)] = value
                }
            }
        }

        let resolved = resolveExecutable(command[0])
        FileHandle.standardError.write(Data("pscht: exec \(resolved)\n".utf8))

        // Flush timings to stderr *before* the child starts writing to the
        // same fd — otherwise they'd be interleaved with the child's output.
        Timings.shared.report()

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
