import Testing
@testable import pscht

@Suite("PschtConfig parsing")
struct PschtConfigTests {
    @Test("Empty TOML yields defaults")
    func emptyDefaults() throws {
        let cfg = try PschtConfigLoader.parse("")
        #expect(cfg.backend == .auto)
        #expect(cfg.dataDir == nil)
        #expect(cfg.tpm2.mode == .pin)
        #expect(cfg.tpm2.device == "/dev/tpmrm0")
        #expect(cfg.tpm2.pcrs.isEmpty)
        #expect(cfg.tpm2.pinPrompt == .tty)
        #expect(cfg.tpm2.argon2.memoryKiB == 262_144)
        #expect(cfg.tpm2.argon2.iterations == 3)
        #expect(cfg.tpm2.argon2.parallelism == 1)
    }

    @Test("Full TPM2 config round-trips")
    func tpm2Full() throws {
        let text = """
            backend = "tpm2"

            [paths]
            data_dir = "/home/alice/.local/share/pscht"

            [tpm2]
            mode = "pin"
            device = "/dev/tpm0"
            pcrs = [7, 11]
            pin_prompt = "systemd"

            [tpm2.argon2]
            memory_kib = 131072
            iterations = 4
            parallelism = 2
            """
        let cfg = try PschtConfigLoader.parse(text)
        #expect(cfg.backend == .tpm2)
        #expect(cfg.dataDir == "/home/alice/.local/share/pscht")
        #expect(cfg.tpm2.device == "/dev/tpm0")
        #expect(cfg.tpm2.pcrs == [7, 11])
        #expect(cfg.tpm2.pinPrompt == .systemd)
        #expect(cfg.tpm2.argon2.memoryKiB == 131_072)
        #expect(cfg.tpm2.argon2.iterations == 4)
        #expect(cfg.tpm2.argon2.parallelism == 2)
    }

    @Test("Invalid backend rejected")
    func invalidBackend() {
        #expect(throws: SecretStoreError.self) {
            try PschtConfigLoader.parse(#"backend = "nope""#)
        }
    }

    @Test("Invalid tpm2.mode rejected")
    func invalidMode() {
        #expect(throws: SecretStoreError.self) {
            try PschtConfigLoader.parse("""
                [tpm2]
                mode = "wrong"
                """)
        }
    }

    @Test("Negative PCR rejected")
    func negativePCR() {
        #expect(throws: SecretStoreError.self) {
            try PschtConfigLoader.parse("""
                [tpm2]
                pcrs = [-1, 7]
                """)
        }
    }

    @Test("effectiveBackend resolves .auto per platform")
    func effectiveBackendAuto() throws {
        var cfg = PschtConfig()
        cfg.backend = .auto
        #if os(macOS)
        #expect(cfg.effectiveBackend == .keychain)
        #else
        #expect(cfg.effectiveBackend == .tpm2)
        #endif
    }
}
