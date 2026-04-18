# pscht

Cross-platform secret manager with hardware-enforced unlock. Stores key-value secrets organized into namespaces, and runs subcommands with those secrets injected as environment variables. Similar in spirit to [envchain](https://github.com/sorah/envchain), but with hardware-backed protection on both macOS and Linux.

| Platform | Backend | Unlock |
|---|---|---|
| macOS 14+ | Keychain + `SecAccessControl(.biometryCurrentSet)` | Touch ID (OS-enforced) |
| Linux (TPM2) | TPM2-sealed 32-byte key + ChaCha20-Poly1305 vault | PIN (TPM hardware-enforced lockout) or presence-only |

On both platforms the unlock is enforced by hardware the pscht binary does not control — modifying pscht can't leak secrets without the unlock.

## Usage

```bash
# macOS one-time: no setup needed (see below for code signing).
# Linux one-time: create the vault. Prompts for a PIN twice.
pscht init                             # PIN mode (default)
pscht init --no-pin                    # presence-only mode (EC2, headless)

# Store secrets (prompts for values without echo)
pscht set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Retrieve a single secret (OS/TPM prompts automatically)
set -gx API_KEY (pscht get myapp API_KEY)

# Run a command with all secrets from a namespace injected as env vars
pscht run aws -- aws s3 ls

# Multiple namespaces at once (one unlock)
pscht run aws,github -- some-tool

# List namespaces / keys (no unlock)
pscht list
pscht list aws

# Delete a key or a namespace
pscht remove aws AWS_ACCESS_KEY_ID
pscht remove aws

# Linux only: rotate the master key and/or change PIN
pscht rekey --change-pin
pscht rekey --to-presence      # switch to presence-only
pscht rekey --to-pin           # switch to PIN mode

# macOS only: re-protect secrets from older (pre-biometric) installs
pscht migrate

# macOS only: store without biometric ACL (scripts, CI)
pscht set --no-bio aws AWS_ACCESS_KEY_ID
```

## Installation

### Nix flake (recommended)

```bash
nix run github:umgefahren/pscht -- --help
```

### Home-Manager module

Add the input to your `flake.nix`:

```nix
{
  inputs = {
    pscht = {
      url = "github:umgefahren/pscht";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
}
```

Then enable it:

```nix
{
  programs.pscht = {
    enable = true;

    # "auto" → keychain on macOS, tpm2 on Linux.
    backend = "auto";

    # --- Linux / TPM2 options (ignored on macOS) ---
    tpm2 = {
      mode = "pin";              # "pin" or "presence"
      device = "/dev/tpmrm0";    # or a TCTI URL with `:`
      pcrs = [ ];                # [ 7 ] to bind to Secure Boot, etc.
    };

    # --- macOS options (ignored on Linux) ---
    # Path to a provisioning profile for the dev.pscht App ID.
    # provisioningProfile = "/path/to/pscht.provisionprofile";
    # signingIdentity = "Apple Development: Your Name (TEAMID)";
  };
}
```

The module writes `~/.config/pscht/config.toml` declaratively. On macOS it also runs the code-signing activation step; on Linux you run `pscht init` manually once (sealing needs a live TPM, which can't happen in a Nix build).

### NixOS module (system-wide, Linux)

```nix
{
  programs.pscht.enable = true;         # installs to environment.systemPackages
  programs.pscht.enableTpmAccess = true; # adds udev rules + `tss` group
}
# Then add your user to the tss group:
# users.users.alice.extraGroups = [ "tss" ];
```

## Linux: TPM2 details

**PIN mode**: the sealed object's auth value is the PIN. Wrong PINs count against the TPM's built-in dictionary-attack protection — after ~32 bad attempts the TPM locks for a cool-down (configured by the motherboard vendor, typically hours). No user-space counter; it's the TPM itself.

**Presence mode**: no PIN. The TPM will unseal for any process on the host. Intended for servers (EC2 NitroTPM, GCP vTPM) where there's no interactive user and physical access is already trusted.

**Vault layout** under `$XDG_DATA_HOME/pscht/`:

| File | Contents |
|---|---|
| `sealed.ctx` | TPM2 sealed object holding a random 32-byte `K_t`. PIN (if any) is the auth value. |
| `vault.enc` | ChaCha20-Poly1305(JSON vault), key = HKDF-SHA256(K_t \|\| Argon2id(PIN, machine-salt)) |
| `index.json` | Cleartext list of namespace/key *names* (not values) for completions |

The Argon2id layer is defense-in-depth above the TPM auth value: if somehow the TPM lockout were bypassed (hardware attack), offline brute-force still hits Argon2's memory cost.

**Backup**: both `sealed.ctx` and `vault.enc` are machine-bound (sealed to this TPM). Moving to a new machine requires re-sealing (`pscht rekey` on the new host after copying `vault.enc`), which requires the current PIN and a live session on the source machine. Back up both files together and plan for TPM replacement / hardware failure.

**PCR binding** is opt-in (`tpm2.pcrs = [ 7 ]`). If enabled, a kernel update or bootloader change that alters the bound PCRs will make the vault unreadable until you `pscht rekey`. Empty list = unbound = no PCR brittleness.

## macOS: code signing

Biometric Keychain ACLs require a signed app bundle with an embedded provisioning profile — ad-hoc signing doesn't work.

1. **Xcode** → Settings → Accounts → add your Apple ID
2. Select your team → **Manage Certificates** → **+** → **Apple Development**
3. Register an App ID `dev.pscht` on [developer.apple.com](https://developer.apple.com/account/resources/identifiers) and download a provisioning profile
4. If `security find-identity -v -p codesigning` shows `CSSMERR_TP_NOT_TRUSTED`:
   ```bash
   curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
   security add-certificates AppleWWDRCAG3.cer
   ```

On `home-manager switch` the module copies the bundle to `~/.local/share/pscht/pscht.app`, embeds the provisioning profile, extracts the entitlements, and code-signs.

## Architecture

```
Sources/pscht/
├── pscht.swift              # @main; registers subcommands (Migrate macOS / Init+Rekey Linux)
├── SecretStore.swift        # cross-platform protocol + CommandContext + VaultError
├── KeychainStore.swift      # #if os(macOS); SecItem*, LAContext
├── TPM2VaultStore.swift     # #if os(Linux); ChaCha20-Poly1305 vault + HKDF
├── TPM2Tools.swift          # subprocess wrapper around tpm2_* tools
├── Argon2.swift             # Swift wrapper over libargon2 (C shim)
├── VaultFile.swift          # on-disk PSCF binary codec; atomic writes
├── MemoryHygiene.swift      # SecretBytes: ~Copyable + mlock + bzero
├── PschtConfig.swift        # config.toml loader (TOMLKit)
├── BiometricOptions.swift   # #if os(macOS); --no-bio flag
└── Commands/
    ├── Set/Get/Run/List/Remove
    ├── Migrate  (macOS only — re-encrypts legacy keychain items)
    └── Init/Rekey  (Linux only — vault lifecycle)

Sources/CArgon2/{module.modulemap, shim.h}   # systemLibrary → libargon2
```

### How `run` works

1. `beginSession()` — one unlock gesture (Touch ID on macOS, PIN prompt + TPM unseal on Linux).
2. For each namespace: `retrieveAll()` pulls every key-value pair from the session.
3. Merge into the inherited environment and spawn the child via `swift-subprocess`. stdin / stdout / stderr pass through.
4. Exit code is forwarded (`128 + signal` on termination by signal).

### What the unlock does *not* protect

- **Namespace and key names are not confidential** on either platform. `list` returns them without prompting (macOS: metadata-only keychain query; Linux: reads `index.json`). Don't encode secrets into key names.
- **Secret values are exposed in the child's environment.** Other processes running as the same UID can read that environment via `ps eww`. Use `run` only for trusted commands.
- **Biometric / PIN auth is required to overwrite or delete a secret** — `SecItemDelete` on macOS and direct vault writes on Linux both require an authenticated session.

### Nix build notes

- macOS: `mkSwiftPackage` from swiftix builds the app bundle. The home-manager activation signs it with the provisioning profile.
- Linux: same `mkSwiftPackage` plus `makeWrapper` to put `tpm2-tools` on `PATH`. `libargon2` is a runtime link-time dep. The Nix build on NixOS needs swiftix's toolchain (Swift 6.3) — nixpkgs only ships 5.10.

## License

MIT
