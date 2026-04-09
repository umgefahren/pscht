# pscht

Store secrets in the macOS Keychain with Touch ID protection. Like [envchain](https://github.com/sorah/envchain), but backed by biometrics.

Secrets are organized into **namespaces** (e.g. `aws`, `github`, `production`). Each namespace holds one or more key-value pairs. Access is gated by Touch ID — no secret leaves the Keychain without your fingerprint.

## Usage

```bash
# Store secrets (prompts for values without echo)
pscht set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Retrieve a single secret (for shell variable assignment)
set -gx API_KEY (pscht get myapp API_KEY)

# Run a command with all secrets from a namespace injected as env vars
pscht run aws -- aws s3 ls

# Multiple namespaces at once
pscht run aws,github -- some-tool

# List all namespaces
pscht list

# List keys in a namespace
pscht list aws

# Remove a single key
pscht remove aws AWS_ACCESS_KEY_ID

# Remove an entire namespace
pscht remove aws

# Skip Touch ID (e.g. in scripts or CI)
pscht get --no-bio aws AWS_ACCESS_KEY_ID
```

## Prerequisites

- macOS (Apple Silicon or Intel)
- Xcode with Command Line Tools installed
- An Apple Development certificate for code signing (free Apple ID works)

### Setting up code signing

pscht needs a signed binary to access the macOS Keychain. A free Apple Developer account is sufficient:

1. Open **Xcode** → Settings → Accounts → add your Apple ID
2. Select your team → **Manage Certificates** → **+** → **Apple Development**
3. If `security find-identity -v -p codesigning` shows `CSSMERR_TP_NOT_TRUSTED`, install the intermediate certificate:
   ```bash
   curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
   security add-certificates AppleWWDRCAG3.cer
   ```
4. Verify: `security find-identity -v -p codesigning` should show a valid identity

## Installation

### Nix flake (recommended)

Try it without installing:

```bash
nix run github:umgefahren/pscht -- --help
```

### Home Manager module

Add the input to your `flake.nix`:

```nix
{
  inputs = {
    # ... your other inputs
    pscht = {
      url = "github:umgefahren/pscht";
      inputs.nixpkgs.follows = "nixpkgs";  # or nixpkgs-unstable
    };
  };

  outputs = { self, nixpkgs, home-manager, pscht, ... }: {
    # In your darwinConfigurations or homeConfigurations:
    home-manager.users.yourname = {
      imports = [
        pscht.homeManagerModules.pscht
      ];
    };
  };
}
```

Then enable it in your home-manager config:

```nix
{
  programs.pscht.enable = true;

  # Optional: pin a specific signing identity (auto-detected by default)
  # programs.pscht.signingIdentity = "Apple Development: Your Name (TEAMID)";
}
```

This will:
- Install the `pscht` binary
- Code-sign it on every `home-manager switch` using your developer certificate
- Install fish shell completions with dynamic namespace/key suggestions

### Build from source

```bash
git clone https://github.com/umgefahren/pscht.git
cd pscht
swift build -c release
# Sign the binary
codesign --force --sign "Apple Development: Your Name (TEAMID)" .build/release/pscht
# Copy to your PATH
cp .build/release/pscht ~/.local/bin/
```

## Architecture

```
pscht
├── Sources/pscht/
│   ├── pscht.swift              # Entry point, root command with subcommands
│   ├── Keychain.swift           # macOS Keychain wrapper (Security framework)
│   ├── BiometricOptions.swift   # Shared --no-bio flag via OptionGroup
│   └── Commands/
│       ├── SetCommand.swift     # Store secrets (readpassphrase, no echo)
│       ├── GetCommand.swift     # Retrieve single secret to stdout
│       ├── RunCommand.swift     # Spawn child process with secrets in env
│       ├── ListCommand.swift    # List namespaces or keys
│       └── RemoveCommand.swift  # Delete keys or namespaces
├── completions/
│   └── pscht.fish               # Fish completions with dynamic lookups
├── flake.nix                    # Nix package + home-manager module
├── pscht.entitlements            # Code signing entitlements
└── Package.swift                # Swift 6.3, swift-argument-parser, swift-subprocess
```

### How secrets are stored

Secrets are stored as `kSecClassGenericPassword` items in the macOS Keychain:

| Keychain attribute | Value |
|---|---|
| `kSecAttrService` | `pscht.<namespace>` |
| `kSecAttrAccount` | Key name (e.g. `AWS_SECRET_ACCESS_KEY`) |
| `kSecValueData` | The secret value (UTF-8 encoded) |
| `kSecAttrAccessible` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |

Items are scoped to the current device and only accessible when the device is unlocked.

### How biometric auth works

Touch ID is enforced at the application level via `LocalAuthentication.LAContext`:

1. Before any read or write, pscht calls `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
2. The system presents the Touch ID prompt
3. Only after successful authentication does pscht proceed to read/write the Keychain
4. The `--no-bio` flag skips this step entirely

This approach works without restricted entitlements or provisioning profiles, unlike Keychain-level biometric access control (`SecAccessControlCreateWithFlags` with `.biometryCurrentSet`) which requires entitlements that aren't available to ad-hoc or development-signed CLI tools.

### How `run` works

The `run` command uses [swift-subprocess](https://github.com/swiftlang/swift-subprocess) to spawn a child process:

1. Authenticate once via Touch ID
2. Retrieve all keys from the requested namespace(s)
3. Spawn the child process with secrets merged into the environment
4. Pass through stdin, stdout, and stderr
5. Forward the child's exit code

### Nix build

The flake builds with Xcode's Swift 6.3 toolchain (nixpkgs only ships Swift 5.10). SwiftPM dependencies are pinned via `fetchFromGitHub` with a generated `workspace-state.json`. The build requires `__noChroot = true` for Xcode access.

The output includes an unsigned binary (`pscht-unsigned`) and a wrapper script that auto-signs it with the first available codesigning identity on first run. The home-manager module goes further: it signs the binary to `~/.local/bin/pscht` on every activation.

## License

MIT
