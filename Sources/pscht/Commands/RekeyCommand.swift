#if os(Linux)
import ArgumentParser
import Foundation
import Glibc

/// Rotate the TPM-sealed master key and/or change the PIN.
///
/// High-level sequence:
/// 1. Open a session (validates the old PIN by successfully unsealing).
/// 2. Generate a fresh random K_t and seal it with the (new) PIN →
///    `sealed.ctx.new`.
/// 3. Re-encrypt the (already-decrypted) vault under the new master key →
///    `vault.enc.new`.
/// 4. Atomically move each `.new` into place, keeping a `.backup` of the
///    displaced file for recovery.
/// 5. Delete the backups.
///
/// If the process is interrupted after step 3 but before step 4 completes
/// for both files, the user must restore manually from the `.backup`s —
/// the backup files are left in place specifically so recovery is possible.
struct RekeyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rekey",
        abstract: "Rotate the TPM-sealed master key (optionally changing PIN/mode)"
    )

    @Flag(name: .long, help: "Prompt for a new PIN (requires pin mode).")
    var changePin: Bool = false

    @Flag(name: .long, help: "Switch to presence-only (no PIN).")
    var toPresence: Bool = false

    @Flag(name: .long, help: "Switch to PIN mode (prompts for new PIN).")
    var toPin: Bool = false

    mutating func run() async throws {
        let ctx = CommandContext.shared
        guard let store = ctx.store as? TPM2VaultStore else {
            throw CleanExit.message("pscht rekey requires backend = \"tpm2\"")
        }

        if toPresence && toPin {
            throw CleanExit.message("--to-presence and --to-pin are mutually exclusive")
        }

        // 1. Open current session. This runs the old PIN check.
        let anySession = try await store.beginSession(reason: "rekey master key")
        guard let session = anySession as? TPM2VaultStore.Session else {
            throw CleanExit.message("internal error: unexpected session type")
        }

        // 2. Decide the new PIN based on flags + current mode.
        let newPin = try decideNewPin(currentMode: ctx.config.tpm2.mode)

        // 3. Perform the rekey on the store.
        try await store.rekey(session: session, newPin: newPin)
        print("pscht: master key rotated")
    }

    private func decideNewPin(currentMode: PschtConfig.Tpm2Mode) throws -> String? {
        if toPresence {
            return nil
        }
        if toPin || changePin {
            guard let a = getpass("New PIN: ") else {
                throw CleanExit.message("Failed to read PIN")
            }
            let first = String(cString: a)
            guard !first.isEmpty else {
                throw CleanExit.message("PIN cannot be empty")
            }
            guard let b = getpass("Confirm PIN: ") else {
                throw CleanExit.message("Failed to read PIN confirmation")
            }
            let second = String(cString: b)
            guard first == second else {
                throw CleanExit.message("PINs do not match")
            }
            return first
        }
        // No flags: keep the same auth factor. If currently in PIN mode,
        // reuse the old PIN (prompt again for it to avoid re-using the
        // session's hidden value and to confirm the user typed it correctly).
        switch currentMode {
        case .pin:
            guard let cstr = getpass("Confirm existing PIN: ") else {
                throw CleanExit.message("Failed to read PIN")
            }
            let pin = String(cString: cstr)
            guard !pin.isEmpty else {
                throw CleanExit.message("PIN cannot be empty")
            }
            return pin
        case .presence:
            return nil
        }
    }
}
#endif
