#if os(Linux)
import ArgumentParser
import Foundation
import Glibc

struct InitCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "init",
        abstract: "Initialize a new TPM2-sealed vault (Linux)"
    )

    @Flag(name: .long, help: "Skip PIN entry; seal with presence only (EC2/servers).")
    var noPin: Bool = false

    mutating func run() async throws {
        let ctx = CommandContext.shared
        guard let tpmStore = ctx.store as? TPM2VaultStore else {
            throw CleanExit.message("pscht init requires backend = \"tpm2\"")
        }

        // Presence-only only works when config agrees — the seal itself has
        // no auth value so the TPM won't ever check one. Require the config
        // to opt in to `mode = "presence"` to avoid a silent mismatch.
        if noPin && ctx.config.tpm2.mode != .presence {
            throw CleanExit.message(
                "--no-pin requires config tpm2.mode = \"presence\" (got \"\(ctx.config.tpm2.mode.rawValue)\")"
            )
        }
        if !noPin && ctx.config.tpm2.mode != .pin {
            throw CleanExit.message(
                "config tpm2.mode = \"\(ctx.config.tpm2.mode.rawValue)\" but no --no-pin flag passed; pass --no-pin or set config to \"pin\""
            )
        }

        let pin: String?
        if noPin {
            pin = nil
        } else {
            pin = try promptNewPin()
        }

        try await tpmStore.initializeVault(pin: pin)
        print("pscht: vault initialized at \(ctx.config.effectiveDataDir.path)")
    }

    /// Prompt twice and require a match. Terminal echo is off.
    private func promptNewPin() throws -> String {
        guard let firstCstr = getpass("Set PIN: ") else {
            throw CleanExit.message("Failed to read PIN")
        }
        let first = String(cString: firstCstr)
        guard !first.isEmpty else {
            throw CleanExit.message("PIN cannot be empty")
        }
        guard let secondCstr = getpass("Confirm PIN: ") else {
            throw CleanExit.message("Failed to read PIN confirmation")
        }
        let second = String(cString: secondCstr)
        guard first == second else {
            throw CleanExit.message("PINs do not match")
        }
        return first
    }
}
#endif
