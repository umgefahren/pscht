# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

pscht is a cross-platform CLI secret manager with hardware-enforced unlock. On macOS it uses the Keychain with Touch ID via `SecAccessControl(.biometryCurrentSet)`. On Linux it seals a master key in the TPM2 (optionally PIN-gated so the TPM enforces lockout) and encrypts the vault with ChaCha20-Poly1305. Secrets are organized into namespaces with key-value pairs. Written in Swift 6.3 with strict concurrency (`swiftLanguageModes: [.v6]`).

## Build & Test

```bash
swift build                                   # debug build
swift build -c release                        # release build
swift test                                    # run tests (Swift Testing)
swift test -Xswiftc -DENABLE_TPM_TESTS        # include TPM integration tests
nix build                                     # full Nix build (macOS or Linux)
```

The Linux dev shell (`nix develop`) provides Swift 6.3 via swiftix plus `tpm2-tools`, `swtpm`, and `libargon2`. macOS uses `apple-sdk_15` + swiftix Swift 6.3.

TPM integration tests expect an `swtpm` simulator at `/tmp/pscht-swtpm/sock`:
```bash
swtpm_setup --tpm2 --tpm-state /tmp/pscht-swtpm
swtpm socket --tpm2 --tpmstate dir=/tmp/pscht-swtpm \
  --server type=unixio,path=/tmp/pscht-swtpm/sock \
  --ctrl type=unixio,path=/tmp/pscht-swtpm/sock.ctrl --daemon
```

macOS: biometric Keychain ACLs require a stable code-signing identity with an embedded provisioning profile (not ad-hoc). The Nix home-manager module signs automatically on activation.

## Architecture

**`SecretStore` protocol** (`Sources/pscht/SecretStore.swift`) is the cross-platform API. Commands call through `CommandContext.shared.store`, which picks the backend at startup based on `config.effectiveBackend` (TOML config or `.auto`). Opaque `SecretStoreSession` is returned from `beginSession(reason:)` — one unlock gesture per invocation.

**macOS: `KeychainStore`** (`#if os(macOS)`). Wraps `SecItem*` / `LAContext`. Service = `pscht.<namespace>`, account = key. Biometric auth is enforced by the OS via `SecAccessControl` with `.biometryCurrentSet`, making it non-bypassable. Legacy-keychain path lives here for `migrate`.

**Linux: `TPM2VaultStore`** (`#if os(Linux)`). Vault layout under `$XDG_DATA_HOME/pscht/`:
- `sealed.ctx` — TPM2 sealed object holding random 32-byte `K_t`. PIN is the auth value if PIN mode.
- `vault.enc` — ChaCha20-Poly1305(JSON) keyed by HKDF-SHA256(K_t || Argon2id(PIN)). AAD binds the header (magic, version, nonce, `sha256(index.json)`).
- `index.json` — cleartext list of namespace/key names for completions (matches macOS's non-secret metadata).

Supporting Linux modules: `TPM2Tools.swift` (subprocess over `tpm2_createprimary`/`tpm2_create`/`tpm2_load`/`tpm2_unseal` with `tpm2_flushcontext` between steps), `Argon2.swift` over `CArgon2` system library target, `MemoryHygiene.swift` with `SecretBytes: ~Copyable` (mlock + explicit_bzero + compile-time non-duplication).

**`VaultFile.swift`** (cross-platform) is the on-disk binary codec. `seal` / `open` run ChaCha20-Poly1305 with header-AAD. Atomic writes use `rename(2)` + directory fsync.

**`PschtConfig`** loads `$XDG_CONFIG_HOME/pscht/config.toml` via TOMLKit. Schema: `backend`, `paths.data_dir`, `tpm2.{mode, device, pcrs, pin_prompt, argon2.*}`. The home-manager module writes this file declaratively.

## Commands

Each command is a `swift-argument-parser` subcommand in `Sources/pscht/Commands/`.

- `set` — reads values from tty (no echo). macOS: only prompts for Touch ID on overwrite. Linux: always opens a session (writes require vault unseal).
- `get` — single secret to stdout.
- `run` — one unlock, retrieves all requested namespaces, spawns child via `swift-subprocess` with merged env.
- `list` — no unlock needed.
- `remove` — requires authenticated session.
- `migrate` (macOS only) — re-encrypts items from legacy keychain.
- `init` (Linux only) — first-run vault bootstrap. `--no-pin` requires `config.tpm2.mode = "presence"`.
- `rekey` (Linux only) — rotates `K_t`, optionally changes PIN / mode. Uses `.backup` files for crash recovery during the swap.

## Nix integration

`flake.nix` exposes:
- `packages.<system>.pscht` — macOS bundle (code-signed by home-manager activation) or Linux `makeWrapper` binary with `tpm2-tools` on PATH and `libargon2` linked.
- `homeManagerModules.pscht` — cross-platform; writes `~/.config/pscht/config.toml` declaratively from `programs.pscht.{backend, dataDir, tpm2.*, signingIdentity, provisioningProfile}`. macOS-only code-signing activation is gated on `pkgs.stdenv.hostPlatform.isDarwin`.
- `nixosModules.pscht` — Linux-only; system-wide install + optional `tss` group / udev rules for `/dev/tpmrm0` access.

The flake uses swiftix (at `github:stillwind-ai/swiftix`) for Swift 6.3 — nixpkgs only ships 5.10. The Linux devShell wires the Swift-bundled clang via `CC`, plus libstdc++ includes (for swift-crypto's BoringSSL) and libc paths.
