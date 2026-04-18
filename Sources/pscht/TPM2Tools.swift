#if os(Linux)
import Foundation
import Subprocess
#if canImport(Glibc)
import Glibc
#endif

/// Thin subprocess wrapper over `tpm2-tools` (`tpm2_createprimary`,
/// `tpm2_create`, `tpm2_load`, `tpm2_unseal`). Used by `TPM2VaultStore` to
/// seal and unseal a 32-byte vault master key with optional PIN-enforced
/// lockout.
enum TPM2Tools {
    struct Config: Sendable {
        /// TPM device path. Actual `tpm2-tools` invocations pick this up via
        /// `TPM2TOOLS_TCTI`; passing `"auto"` here disables the override.
        var device: String
    }

    /// Set up `TPM2TOOLS_TCTI` for the tpm2-tools subprocesses given our
    /// device path. Returns a pair of env overrides to overlay onto the
    /// inherited environment.
    static func envOverrides(device: String) -> [Environment.Key: String?] {
        if device == "auto" || device.isEmpty {
            return [:]
        }
        // Map `/dev/tpmrm0` → `device:/dev/tpmrm0`; pass through if the
        // caller already gave us a TCTI URL (contains a colon).
        let tcti = device.contains(":") ? device : "device:\(device)"
        return [Environment.Key(stringLiteral: "TPM2TOOLS_TCTI"): tcti]
    }

    /// Seal `key` under a newly-created primary with an optional `pin`.
    /// Writes the loaded sealed-object context to `sealedContextPath`.
    /// The temporary primary context, pub/priv blobs, and input key file
    /// are created in a per-invocation tmpfs dir and wiped before returning.
    static func seal(
        key: borrowing SecretBytes,
        pin: String?,
        config: Config,
        sealedContextPath: URL
    ) async throws(SecretStoreError) {
        let work = try TempDir.makeSecure(prefix: "pscht-seal")
        defer { work.cleanup() }

        // Materialise the plaintext key as a file the TPM tools can read.
        let keyPath = work.url.appendingPathComponent("key.bin")
        do {
            try key.withBytes { buf throws(SecretStoreError) in
                do {
                    try Data(bytes: buf.baseAddress!, count: buf.count)
                        .write(to: keyPath, options: .atomic)
                } catch {
                    throw .atomicWriteFailed("write key.bin: \(error.localizedDescription)")
                }
            }
            try setMode0600(keyPath)
        }

        let primaryPath = work.url.appendingPathComponent("primary.ctx")
        let pubPath = work.url.appendingPathComponent("sealed.pub")
        let privPath = work.url.appendingPathComponent("sealed.priv")

        let env = envOverrides(device: config.device)

        // Each tpm2_* invocation can leave transient objects loaded on some
        // TPM implementations (notably swtpm). Flushing before each step
        // keeps the handle table clean and costs microseconds.
        try await flushTransient(envOverrides: env)

        // 1) Primary key under owner hierarchy.
        try await runTool("tpm2_createprimary", [
            "-C", "o",
            "-c", primaryPath.path,
        ], envOverrides: env)
        try await flushTransient(envOverrides: env)

        // 2) Create a sealed object holding the 32-byte key. PIN becomes the
        //    auth value on the sealed object itself, so the TPM (not pscht)
        //    enforces dictionary-attack lockout.
        var createArgs: [String] = [
            "-C", primaryPath.path,
            "-i", keyPath.path,
            "-u", pubPath.path,
            "-r", privPath.path,
        ]
        if let pin, !pin.isEmpty {
            let pinPath = try writePinFile(pin: pin, in: work.url)
            createArgs.append("-p")
            createArgs.append("file:\(pinPath.path)")
        }
        try await runTool("tpm2_create", createArgs, envOverrides: env)
        try await flushTransient(envOverrides: env)

        // 3) Load the sealed object into a persistent context file the
        //    caller controls.
        try await runTool("tpm2_load", [
            "-C", primaryPath.path,
            "-u", pubPath.path,
            "-r", privPath.path,
            "-c", sealedContextPath.path,
        ], envOverrides: env)
        try await flushTransient(envOverrides: env)

        try setMode0600(sealedContextPath)
    }

    private static func flushTransient(envOverrides env: [Environment.Key: String?]) async throws(SecretStoreError) {
        _ = try? await runTool("tpm2_flushcontext", ["--transient-object"], envOverrides: env)
    }

    /// Unseal the 32-byte key inside `sealedContextPath`. Interprets wrong-PIN
    /// and lockout states from tpm2_unseal's stderr and maps them to
    /// `SecretStoreError` cases with actionable messages.
    static func unseal(
        sealedContextPath: URL,
        pin: String?,
        config: Config
    ) async throws(SecretStoreError) -> SecretBytes {
        let work = try TempDir.makeSecure(prefix: "pscht-unseal")
        defer { work.cleanup() }

        var args: [String] = ["-c", sealedContextPath.path]
        if let pin, !pin.isEmpty {
            let pinPath = try writePinFile(pin: pin, in: work.url)
            args.append("-p")
            args.append("file:\(pinPath.path)")
        }

        let env = envOverrides(device: config.device)
        try await flushTransient(envOverrides: env)
        let result = try await runToolCapturingStdout("tpm2_unseal", args, envOverrides: env)
        try await flushTransient(envOverrides: env)

        // tpm2_unseal writes raw binary to stdout.
        guard result.stdout.count > 0 else {
            throw .vaultCorrupt("tpm2_unseal returned empty output")
        }
        var out = SecretBytes(count: result.stdout.count)
        let _: Void = try out.withMutableBytes { buf throws(SecretStoreError) in
            result.stdout.copyBytes(to: buf)
        }
        return out
    }

    // MARK: - Internals

    private struct ToolResult: Sendable {
        let stdout: Data
        let stderr: String
    }

    private static func runTool(
        _ tool: String,
        _ args: [String],
        envOverrides: [Environment.Key: String?]
    ) async throws(SecretStoreError) {
        _ = try await runToolCapturingStdout(tool, args, envOverrides: envOverrides)
    }

    private static func runToolCapturingStdout(
        _ tool: String,
        _ args: [String],
        envOverrides: [Environment.Key: String?]
    ) async throws(SecretStoreError) -> ToolResult {
        let subprocessResult: ExecutionRecord<DataOutput, StringOutput<UTF8>>
        do {
            subprocessResult = try await Subprocess.run(
                .name(tool),
                arguments: Arguments(args),
                environment: .inherit.updating(envOverrides),
                output: .data(limit: 64 * 1024),
                error: .string(limit: 64 * 1024, encoding: UTF8.self)
            )
        } catch {
            // Most common: ENOENT — binary not on PATH.
            throw .backendUnavailable("\(tool) failed to launch: \(error.localizedDescription)")
        }

        let stdout = subprocessResult.standardOutput
        let stderr = subprocessResult.standardError ?? ""

        switch subprocessResult.terminationStatus {
        case .exited(0):
            return ToolResult(stdout: stdout, stderr: stderr)
        case .exited(let code):
            throw Self.interpretError(tool: tool, exit: code, stderr: stderr)
        case .signaled(let sig):
            throw .backendUnavailable("\(tool) killed by signal \(sig)")
        }
    }

    /// Map tpm2-tools stderr into PIN-related errors where we can recognize
    /// them, and fall through to a generic `subprocessFailed`-ish message
    /// otherwise. Lockout and bad-auth detection is best-effort; the kernel
    /// TPM resource manager produces different strings across versions.
    private static func interpretError(tool: String, exit: Int32, stderr: String) -> SecretStoreError {
        let lower = stderr.lowercased()
        if lower.contains("lockout") {
            return .tpmLockedOut(retryAfterSeconds: nil)
        }
        if lower.contains("authorization") || lower.contains("authvalue") {
            // tpm2_unseal on wrong PIN: "the authorization HMAC check failed"
            return .pinIncorrect(attemptsRemaining: nil)
        }
        if lower.contains("no such file or directory") && lower.contains("/dev/tpm") {
            return .tpmDeviceMissing(path: "/dev/tpmrm0")
        }
        return .backendUnavailable("\(tool) exited with \(exit): \(stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
    }

    private static func writePinFile(pin: String, in dir: URL) throws(SecretStoreError) -> URL {
        let path = dir.appendingPathComponent("pin.txt")
        let data = Data(pin.utf8)
        do {
            try data.write(to: path, options: .atomic)
        } catch {
            throw .atomicWriteFailed("write pin file: \(error.localizedDescription)")
        }
        try setMode0600(path)
        return path
    }

    private static func setMode0600(_ url: URL) throws(SecretStoreError) {
        do {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        } catch {
            throw .atomicWriteFailed("chmod 0600 \(url.path): \(error.localizedDescription)")
        }
    }
}

/// Tmpfs-backed scratch directory (`$XDG_RUNTIME_DIR` or `/dev/shm`) where
/// PIN files and key material live for the duration of a single
/// tpm2-tools invocation. Reference-type so `defer { t.cleanup() }` works
/// (noncopyable types can't be captured by escaping closures). Cleanup
/// wipes contents before unlinking — best-effort but blocks the obvious
/// leaks.
final class TempDir: @unchecked Sendable {
    let url: URL

    private init(url: URL) { self.url = url }

    static func makeSecure(prefix: String) throws(SecretStoreError) -> TempDir {
        let base = preferredRuntimeDirectory()
        let dir = base.appendingPathComponent("\(prefix)-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .atomicWriteFailed("create temp dir: \(error.localizedDescription)")
        }
        return TempDir(url: dir)
    }

    private static func preferredRuntimeDirectory() -> URL {
        let env = ProcessInfo.processInfo.environment
        if let xdg = env["XDG_RUNTIME_DIR"], !xdg.isEmpty {
            return URL(fileURLWithPath: xdg)
        }
        // /dev/shm is world-writable but sticky; our own 0700 subdir keeps
        // peers out.
        return URL(fileURLWithPath: "/dev/shm")
    }

    func cleanup() {
        // Walk any remaining files and overwrite with zeros before unlink.
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: url.path) {
            for name in entries {
                let file = url.appendingPathComponent(name)
                if var data = try? Data(contentsOf: file) {
                    data.resetBytes(in: 0..<data.count)
                    try? data.write(to: file, options: .atomic)
                }
                try? FileManager.default.removeItem(at: file)
            }
        }
        try? FileManager.default.removeItem(at: url)
    }

    deinit {
        // Safety net if caller forgot to cleanup().
        try? FileManager.default.removeItem(at: url)
    }
}
#endif
