# pscht

Store secrets in the macOS Keychain with Touch ID protection. Like [envchain](https://github.com/sorah/envchain), but backed by biometrics.

Secrets are organized into **namespaces** (e.g. `aws`, `github`, `production`). Each namespace holds one or more key-value pairs. Biometric protection is enforced at the Keychain level via `SecAccessControl` with `.biometryCurrentSet` — the OS itself prompts for Touch ID on every read, so the check cannot be bypassed by the calling process.

## Usage

```bash
# Store secrets (prompts for values without echo)
pscht set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Retrieve a single secret (Touch ID prompted by the OS)
set -gx API_KEY (pscht get myapp API_KEY)

# Run a command with all secrets from a namespace injected as env vars
pscht run aws -- aws s3 ls

# Multiple namespaces at once (single Touch ID prompt)
pscht run aws,github -- some-tool

# List all namespaces
pscht list

# List keys in a namespace
pscht list aws

# Remove a single key
pscht remove aws AWS_ACCESS_KEY_ID

# Remove an entire namespace (prompts for confirmation)
pscht remove aws

# Store without biometric protection (e.g. for scripts or CI)
pscht set --no-bio aws AWS_ACCESS_KEY_ID

# Re-protect secrets originally stored without biometric ACLs
pscht migrate
```

## Prerequisites

- macOS 14+ (Apple Silicon or Intel)
- Xcode with Command Line Tools installed
- An Apple Developer account (free tier works) with:
  - An **Apple Development** signing certificate
  - A **provisioning profile** for the `dev.pscht` App ID

Biometric Keychain ACLs require the data protection keychain, which in turn requires a signed app bundle with an embedded provisioning profile. Ad-hoc signing is not sufficient.

### Setting up code signing

1. Open **Xcode** → Settings → Accounts → add your Apple ID
2. Select your team → **Manage Certificates** → **+** → **Apple Development**
3. Register an App ID `dev.pscht` on [developer.apple.com](https://developer.apple.com/account/resources/identifiers) and download a development provisioning profile for it
4. If `security find-identity -v -p codesigning` shows `CSSMERR_TP_NOT_TRUSTED`, install the WWDR intermediate:
   ```bash
   curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
   security add-certificates AppleWWDRCAG3.cer
   ```
5. Verify: `security find-identity -v -p codesigning` should show a valid identity

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
  programs.pscht = {
    enable = true;

    # Required: path to a provisioning profile for the dev.pscht App ID.
    # Can be a plain path or a sops-managed secret.
    provisioningProfile = "/path/to/pscht.provisionprofile";

    # Optional: pin a specific signing identity (auto-detected by default)
    # signingIdentity = "Apple Development: Your Name (TEAMID)";
  };
}
```

On every `home-manager switch` this will:
- Install the pscht app bundle to `~/.local/share/pscht/pscht.app`
- Embed the provisioning profile, extract its entitlements, and code-sign the bundle
- Install a wrapper on `$PATH` that invokes the signed bundle
- Install fish shell completions with dynamic namespace/key suggestions

### Build from source

```bash
git clone https://github.com/umgefahren/pscht.git
cd pscht
swift build -c release

# Assemble the app bundle
BUNDLE=.build/release/pscht.app/Contents
mkdir -p "$BUNDLE/MacOS"
cp .build/release/pscht "$BUNDLE/MacOS/pscht"
cp Info.plist "$BUNDLE/Info.plist"

# Embed the provisioning profile and extract its entitlements
cp /path/to/pscht.provisionprofile "$BUNDLE/embedded.provisionprofile"
security cms -D -i "$BUNDLE/embedded.provisionprofile" > /tmp/profile.plist
/usr/libexec/PlistBuddy -c "Print :Entitlements" -x /tmp/profile.plist > /tmp/pscht.entitlements

# Sign with the profile's entitlements
codesign --force \
  --sign "Apple Development: Your Name (TEAMID)" \
  --entitlements /tmp/pscht.entitlements \
  .build/release/pscht.app

# Run via the bundle's executable
.build/release/pscht.app/Contents/MacOS/pscht --help
```

## Architecture

```
pscht
├── Sources/pscht/
│   ├── pscht.swift                # Entry point, root command with subcommands
│   ├── Keychain.swift             # macOS Keychain wrapper (Security framework)
│   ├── BiometricOptions.swift     # Shared --no-bio flag via OptionGroup
│   └── Commands/
│       ├── SetCommand.swift       # Store secrets (readpassphrase, no echo)
│       ├── GetCommand.swift       # Retrieve single secret to stdout
│       ├── RunCommand.swift       # Spawn child process with secrets in env
│       ├── ListCommand.swift      # List namespaces or keys
│       ├── RemoveCommand.swift    # Delete keys or namespaces
│       └── MigrateCommand.swift   # Re-store legacy secrets with biometric ACL
├── completions/
│   └── pscht.fish                 # Fish completions with dynamic lookups
├── flake.nix                      # Nix package + home-manager module
├── Info.plist                     # App bundle metadata (CFBundleIdentifier=dev.pscht)
├── pscht.entitlements             # Placeholder entitlements (real ones come from the provisioning profile)
└── Package.swift                  # Swift 6.3, swift-argument-parser, swift-subprocess
```

### How secrets are stored

Secrets are stored as `kSecClassGenericPassword` items in the macOS **data protection keychain**:

| Keychain attribute | Value |
|---|---|
| `kSecClass` | `kSecClassGenericPassword` |
| `kSecAttrService` | `pscht.<namespace>` |
| `kSecAttrAccount` | Key name (e.g. `AWS_SECRET_ACCESS_KEY`) |
| `kSecValueData` | The secret value (UTF-8 encoded) |
| `kSecUseDataProtectionKeychain` | `true` |
| `kSecAttrAccessControl` *(biometric)* | `SecAccessControl(.biometryCurrentSet, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)` |
| `kSecAttrAccessible` *(non-biometric)* | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |

Items are scoped to the current device, invalidated if the enrolled biometric set changes, and require a device passcode to be set.

### How biometric auth works

Touch ID is enforced **at the Keychain level** by the OS — not by the pscht process:

1. pscht creates an `LAContext`, calls `evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` once, and passes the authenticated context into the keychain query via `kSecUseAuthenticationContext`.
2. The Security framework validates the Touch ID evaluation against each item's `SecAccessControl` and returns the plaintext only if it succeeds.
3. Because the check is performed by the OS against an ACL attached to the item, it cannot be skipped by modifying the pscht binary or intercepting its calls.

`--no-bio` on `set` stores an item without a `SecAccessControl` ACL, so the Keychain will return it without any biometric check. The `get` and `remove` commands have no `--no-bio` flag — a biometric prompt is always required. `list` never prompts.

### What biometric auth does *not* protect

- **Namespace and key names are not confidential.** `list` and `list <namespace>` return them without prompting, because the Keychain query asks only for `kSecAttrService` / `kSecAttrAccount` and doesn't touch `kSecValueData`. Don't encode secrets into key names.
- **Secret values are not confidential once injected via `run`.** A child process started via `pscht run` inherits the secrets as environment variables, and so does every descendant in its process tree. Other processes running as the same UID can read that environment (e.g. `ps eww`). Use `run` only to feed trusted commands; don't use it to pass secrets to sandboxed or multi-tenant workloads.
- **Biometric auth is required to overwrite or delete a secret** (since pscht 0.1.x) — `SecItemDelete` on its own does not consult the item's ACL, so pscht pre-authenticates an `LAContext` before any destructive keychain operation.

The `migrate` command reads items from the **legacy keychain** (items stored by older versions of pscht that didn't set `kSecUseDataProtectionKeychain`) and rewrites them into the data protection keychain with a biometric ACL.

### How `run` works

The `run` command uses [swift-subprocess](https://github.com/swiftlang/swift-subprocess) to spawn a child process:

1. Authenticate once via `LAContext.evaluatePolicy` — the user sees a single Touch ID prompt
2. Issue a single `SecItemCopyMatching` query per namespace, using the authenticated context, so every biometric-protected item in the namespace is unlocked by that one prompt
3. Merge the retrieved key-value pairs into the inherited environment
4. Spawn the child command, passing through stdin, stdout, and stderr
5. Forward the child's exit code (or `128 + signal` on termination by signal)

### Nix build

The flake builds with Xcode's Swift 6.3 toolchain (nixpkgs only ships Swift 5.10). SwiftPM dependencies are pinned via `fetchFromGitHub` with a generated `workspace-state.json`. The build requires `__noChroot = true` for Xcode access.

The derivation produces the pscht app bundle plus a `pscht-sign` helper script. The home-manager module invokes `pscht-sign` on every activation to embed the provisioning profile, extract its entitlements, and code-sign the bundle in `~/.local/share/pscht/pscht.app`. A thin wrapper on `$PATH` execs into the bundle.

## License

MIT
