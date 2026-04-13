# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

pscht is a macOS CLI tool for storing and managing secrets in the native macOS Keychain with biometric (Touch ID) protection. Secrets are organized into namespaces with key-value pairs. Written in Swift 6.3 with strict concurrency (`swiftLanguageModes: [.v6]`).

## Build & Test

```bash
swift build                    # debug build
swift build -c release         # release build
swift test                     # run tests (Swift Testing framework)
nix build                      # nix build (handles code signing)
```

Code signing is required for Keychain access at runtime:
```bash
codesign --force --sign "Apple Development: ..." .build/release/pscht
```

## Architecture

**Keychain.swift** is the core abstraction — wraps macOS Security framework (`SecItem*`) for CRUD on `kSecClassGenericPassword` items. Secrets use service `pscht.<namespace>` and account = key name. Biometric auth is enforced at application level via `LAContext` (not Keychain ACLs), which allows ad-hoc code signing.

**Commands/** contains five `swift-argument-parser` subcommands:
- `set` — interactive input via `readpassphrase()` (no echo)
- `get` — prints single secret to stdout
- `run` — spawns child process (via `swift-subprocess`) with namespace secrets injected as env vars
- `list` — lists namespaces or keys (no biometric required)
- `remove` — deletes keys or entire namespaces with confirmation

**BiometricOptions.swift** defines the shared `--no-bio` flag used across commands.

**Nix integration:** `flake.nix` provides a build derivation and a home-manager module that handles code signing on activation (overwrites the signed binary in place).
