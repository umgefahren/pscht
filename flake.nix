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

            # pscht needs entitlements for Keychain biometrics, so install
            # the unsigned binary + a wrapper that code-signs on first run.
            installPhase = ''
              runHook preInstall

              mkdir -p $out/bin $out/share/pscht
              cp "$(find .build/release -maxdepth 1 -name pscht -type f)" $out/bin/pscht-unsigned
              cp ${./pscht.entitlements} $out/share/pscht/pscht.entitlements

              # Wrapper that code-signs on first run
              cat > $out/bin/pscht << WRAPPER
              #!/bin/bash
              PSCHT_BIN="\$HOME/.local/bin/pscht"
              PSCHT_UNSIGNED="$out/bin/pscht-unsigned"

              if [ ! -f "\$PSCHT_BIN" ] || [ "\$PSCHT_UNSIGNED" -nt "\$PSCHT_BIN" ]; then
                mkdir -p "\$(dirname "\$PSCHT_BIN")"
                cp "\$PSCHT_UNSIGNED" "\$PSCHT_BIN"
                chmod +x "\$PSCHT_BIN"
                IDENTITY=\$(/usr/bin/security find-identity -v -p codesigning | head -1 | sed 's/.*"\(.*\)".*/\1/')
                if [ -n "\$IDENTITY" ]; then
                  /usr/bin/codesign --force --sign "\$IDENTITY" "\$PSCHT_BIN" 2>/dev/null
                fi
              fi

              exec "\$PSCHT_BIN" "\$@"
              WRAPPER
              chmod +x $out/bin/pscht

              runHook postInstall
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
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            xdg.configFile."fish/completions/pscht.fish".source = ./completions/pscht.fish;

            home.activation.pscht-codesign = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
              PSCHT_UNSIGNED="${cfg.package}/bin/pscht-unsigned"
              PSCHT_BIN="$HOME/.local/bin/pscht"

              ${
                if cfg.signingIdentity != null then
                  ''IDENTITY="${cfg.signingIdentity}"''
                else
                  ''IDENTITY=$(/usr/bin/security find-identity -v -p codesigning | head -1 | sed 's/.*"\(.*\)".*/\1/')''
              }

              if [ -n "$IDENTITY" ]; then
                mkdir -p "$(dirname "$PSCHT_BIN")"
                [ -f "$PSCHT_BIN" ] && chmod u+w "$PSCHT_BIN"
                cp "$PSCHT_UNSIGNED" "$PSCHT_BIN"
                chmod +x "$PSCHT_BIN"
                /usr/bin/codesign --force --sign "$IDENTITY" "$PSCHT_BIN" 2>/dev/null
                run echo "pscht: signed with $IDENTITY"
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
