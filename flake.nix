{
  description = "pscht - Store secrets in macOS Keychain with biometric protection";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    swiftix.url = "github:stillwind-ai/swiftix";
  };

  outputs =
    { self, nixpkgs, swiftix }:
    let
      supportedSystems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          mkSwiftPackage = swiftix.lib.mkSwiftPackage { inherit pkgs; };
          swiftpm2nixHelpers = swiftix.lib.swiftpm2nixHelpers { inherit pkgs; };
        in
        {
          default = self.packages.${system}.pscht;

          pscht = mkSwiftPackage {
            pname = "pscht";
            version = "0.1.0";
            src = pkgs.lib.cleanSource ./.;
            swift = swiftix.packages.${system}.swift-6_3;
            swiftpmGenerated = swiftpm2nixHelpers ./nix;
            executableName = "pscht";

            # Package the binary into an app bundle structure for signing.
            # Biometric keychain ACLs require the data protection keychain,
            # which needs a provisioning profile embedded in an app bundle.
            postInstall = ''
              # Build the .app bundle
              BUNDLE="$out/Applications/pscht.app/Contents"
              mkdir -p "$BUNDLE/MacOS"
              mv $out/bin/pscht "$BUNDLE/MacOS/pscht"
              cp ${./Info.plist} "$BUNDLE/Info.plist"

              # pscht-sign: embeds provisioning profile, extracts its entitlements,
              # and signs the app bundle.
              cat > $out/bin/pscht-sign << 'SIGN'
#!/bin/bash
set -euo pipefail
BUNDLE="$1"
IDENTITY="$2"
PROFILE="$3"

# Embed provisioning profile
cp "$PROFILE" "$BUNDLE/Contents/embedded.provisionprofile"

# Extract entitlements from the provisioning profile
DECODED=$(mktemp)
ENTITLEMENTS=$(mktemp)
trap 'rm -f "$DECODED" "$ENTITLEMENTS"' EXIT
/usr/bin/security cms -D -i "$PROFILE" > "$DECODED"
/usr/libexec/PlistBuddy -c "Print :Entitlements" -x "$DECODED" > "$ENTITLEMENTS"

# Sign with the profile's entitlements
/usr/bin/codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" "$BUNDLE"
SIGN
              chmod +x $out/bin/pscht-sign

              # Wrapper script for direct invocation
              cat > $out/bin/pscht << 'WRAPPER'
#!/bin/bash
PSCHT_APP="$HOME/.local/share/pscht/pscht.app"
exec "$PSCHT_APP/Contents/MacOS/pscht" "$@"
WRAPPER
              chmod +x $out/bin/pscht
            '';

            meta = {
              description = "Store secrets in macOS Keychain with biometric protection";
              platforms = pkgs.lib.platforms.darwin;
              mainProgram = "pscht";
            };
          };
        }
      );

      homeManagerModules.default = self.homeManagerModules.pscht;

      homeManagerModules.pscht =
        {
          lib,
          pkgs,
          config,
          ...
        }:
        let
          cfg = config.programs.pscht;
          system = pkgs.stdenv.hostPlatform.system;
        in
        {
          options.programs.pscht = {
            enable = lib.mkEnableOption "pscht - macOS Keychain secret manager";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${system}.pscht;
              description = "The pscht package to install.";
            };

            signingIdentity = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "Apple Development: Your Name (TEAMID)";
              description = ''
                Code signing identity for macOS Keychain access.
                If null, pscht will auto-detect the first available identity.
              '';
            };

            provisioningProfile = lib.mkOption {
              type = lib.types.str;
              description = ''
                Path to a macOS provisioning profile for the dev.pscht App ID.
                Required for biometric keychain ACLs. Can be a sops secret path.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            xdg.configFile."fish/completions/pscht.fish".source = ./completions/pscht.fish;

            home.activation.pscht-codesign = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
              PSCHT_APP="$HOME/.local/share/pscht/pscht.app"
              SRC_BUNDLE="${cfg.package}/Applications/pscht.app"

              ${
                if cfg.signingIdentity != null then
                  ''IDENTITY="${cfg.signingIdentity}"''
                else
                  ''IDENTITY=$(/usr/bin/security find-identity -v -p codesigning | head -1 | sed 's/.*"\(.*\)".*/\1/')''
              }

              # Clean up legacy binary from pre-app-bundle versions
              rm -f "$HOME/.local/bin/pscht"

              if [ -n "$IDENTITY" ]; then
                # Copy the app bundle (needs to be writable for signing)
                rm -rf "$PSCHT_APP"
                mkdir -p "$(dirname "$PSCHT_APP")"
                cp -R "$SRC_BUNDLE" "$PSCHT_APP"
                chmod -R u+w "$PSCHT_APP"

                # Sign with provisioning profile and entitlements
                ${cfg.package}/bin/pscht-sign "$PSCHT_APP" "$IDENTITY" "${cfg.provisioningProfile}"

                run echo "pscht: signed app bundle with $IDENTITY"
              else
                run echo "pscht: WARNING - no codesigning identity found, biometrics will not work"
              fi
            '';
          };
        };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          swift = swiftix.packages.${system}.swift-6_3;
        in
        {
          default = pkgs.mkShell {
            packages = [ swift pkgs.apple-sdk_15 ];
            shellHook = ''
              export SDKROOT="${pkgs.apple-sdk_15}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
            '';
          };
        }
      );
    };
}
