import Foundation
import TOMLKit

/// Configuration read from `$XDG_CONFIG_HOME/pscht/config.toml` (default
/// `~/.config/pscht/config.toml`). Missing file → all defaults.
///
/// The home-manager / NixOS module is the authoritative source; pscht never
/// writes to this file. CLI flags override TOML values *except* `backend`,
/// which TOML always wins so Nix config is deterministic.
struct PschtConfig: Sendable {
    enum Backend: String, Sendable {
        case keychain
        case tpm2
        case auto
    }

    enum Tpm2Mode: String, Sendable {
        case pin
        case presence
    }

    enum PinPrompt: String, Sendable {
        case tty
        case systemd
    }

    struct Argon2Params: Sendable {
        var memoryKiB: Int = 262_144
        var iterations: Int = 3
        var parallelism: Int = 1
    }

    struct Tpm2Config: Sendable {
        var mode: Tpm2Mode = .pin
        var device: String = "/dev/tpmrm0"
        var pcrs: [Int] = []
        var pinPrompt: PinPrompt = .tty
        var argon2: Argon2Params = .init()
    }

    var backend: Backend = .auto
    var dataDir: String? = nil
    var tpm2: Tpm2Config = .init()

    /// Resolved backend. `.auto` picks keychain on macOS and tpm2 on Linux.
    var effectiveBackend: Backend {
        switch backend {
        case .auto:
            #if os(macOS)
            return .keychain
            #else
            return .tpm2
            #endif
        case .keychain, .tpm2:
            return backend
        }
    }

    /// Resolved data directory (`$XDG_DATA_HOME/pscht` when unset).
    var effectiveDataDir: URL {
        if let dataDir {
            return URL(fileURLWithPath: (dataDir as NSString).expandingTildeInPath)
        }
        let env = ProcessInfo.processInfo.environment
        if let xdg = env["XDG_DATA_HOME"], !xdg.isEmpty {
            return URL(fileURLWithPath: xdg).appendingPathComponent("pscht")
        }
        let home = env["HOME"] ?? NSHomeDirectory()
        return URL(fileURLWithPath: home)
            .appendingPathComponent(".local/share/pscht")
    }
}

enum PschtConfigLoader {
    /// Load config from the default location, or return defaults if absent.
    static func load() throws(SecretStoreError) -> PschtConfig {
        let path = defaultConfigPath()
        guard FileManager.default.fileExists(atPath: path.path) else {
            return PschtConfig()
        }
        do {
            let text = try String(contentsOf: path, encoding: .utf8)
            return try parse(text)
        } catch let error as SecretStoreError {
            throw error
        } catch {
            throw .configInvalid("reading \(path.path): \(error.localizedDescription)")
        }
    }

    static func parse(_ text: String) throws(SecretStoreError) -> PschtConfig {
        let table: TOMLTable
        do {
            table = try TOMLTable(string: text)
        } catch {
            throw .configInvalid("TOML parse error: \(error)")
        }

        var cfg = PschtConfig()

        if let backendRaw = table["backend"]?.string {
            guard let backend = PschtConfig.Backend(rawValue: backendRaw) else {
                throw .configInvalid("backend must be one of: keychain, tpm2, auto (got '\(backendRaw)')")
            }
            cfg.backend = backend
        }

        if let paths = table["paths"]?.table, let dd = paths["data_dir"]?.string {
            cfg.dataDir = dd
        }

        if let tpm = table["tpm2"]?.table {
            if let modeRaw = tpm["mode"]?.string {
                guard let mode = PschtConfig.Tpm2Mode(rawValue: modeRaw) else {
                    throw .configInvalid("tpm2.mode must be 'pin' or 'presence' (got '\(modeRaw)')")
                }
                cfg.tpm2.mode = mode
            }
            if let device = tpm["device"]?.string {
                cfg.tpm2.device = device
            }
            if let pcrsArr = tpm["pcrs"]?.array {
                var pcrs: [Int] = []
                for element in pcrsArr {
                    guard let n = element.int, n >= 0 else {
                        throw .configInvalid("tpm2.pcrs must be a list of non-negative integers")
                    }
                    pcrs.append(n)
                }
                cfg.tpm2.pcrs = pcrs
            }
            if let promptRaw = tpm["pin_prompt"]?.string {
                guard let prompt = PschtConfig.PinPrompt(rawValue: promptRaw) else {
                    throw .configInvalid("tpm2.pin_prompt must be 'tty' or 'systemd' (got '\(promptRaw)')")
                }
                cfg.tpm2.pinPrompt = prompt
            }
            if let argon = tpm["argon2"]?.table {
                if let m = argon["memory_kib"]?.int, m > 0 {
                    cfg.tpm2.argon2.memoryKiB = m
                }
                if let i = argon["iterations"]?.int, i > 0 {
                    cfg.tpm2.argon2.iterations = i
                }
                if let p = argon["parallelism"]?.int, p > 0 {
                    cfg.tpm2.argon2.parallelism = p
                }
            }
        }

        return cfg
    }

    private static func defaultConfigPath() -> URL {
        let env = ProcessInfo.processInfo.environment
        let base: URL
        if let xdg = env["XDG_CONFIG_HOME"], !xdg.isEmpty {
            base = URL(fileURLWithPath: xdg)
        } else {
            let home = env["HOME"] ?? NSHomeDirectory()
            base = URL(fileURLWithPath: home).appendingPathComponent(".config")
        }
        return base.appendingPathComponent("pscht/config.toml")
    }
}
