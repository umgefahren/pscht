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

A stable code signing identity is required for Keychain biometric ACLs at runtime:
```bash
codesign --force --sign "Apple Development: ..." --entitlements pscht.entitlements .build/release/pscht
```

## Architecture

**Keychain.swift** is the core abstraction — wraps macOS Security framework (`SecItem*`) for CRUD on `kSecClassGenericPassword` items. Secrets use service `pscht.<namespace>` and account = key name. Biometric auth is enforced at the Keychain level via `SecAccessControl` with `.biometryCurrentSet` — the OS itself prompts for Touch ID on retrieval, making it non-bypassable. This requires a stable code signing identity (not ad-hoc).

**Commands/** contains five `swift-argument-parser` subcommands:
- `set` — interactive input via `readpassphrase()` (no echo); `--no-bio` stores without biometric ACL
- `get` — prints single secret to stdout; Touch ID prompted by the Keychain automatically
- `run` — spawns child process (via `swift-subprocess`) with namespace secrets injected as env vars; pre-authenticates once to avoid repeated prompts
- `list` — lists namespaces or keys (no biometric required)
- `remove` — deletes keys or entire namespaces with confirmation

**BiometricOptions.swift** defines the `--no-bio` flag used by `set` to store secrets without biometric protection.

**Nix integration:** `flake.nix` provides a build derivation and a home-manager module that handles code signing with entitlements on activation.
