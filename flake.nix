{
  description = "pscht - Store secrets in macOS Keychain with biometric protection";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
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

          swift-argument-parser = pkgs.fetchFromGitHub {
            owner = "apple";
            repo = "swift-argument-parser";
            rev = "626b5b7b2f45e1b0b1c6f4a309296d1d21d7311b";
            hash = "sha256-90ECc3iEmxvOUk9iLKbQdQEz88dOisPqWsJLOFcKUV8=";
          };
          swift-subprocess = pkgs.fetchFromGitHub {
            owner = "swiftlang";
            repo = "swift-subprocess";
            rev = "13d087685b95d64d6aac9b94500d347bbe84c39b";
            hash = "sha256-8Ujur2TwISoXo9LZ2Kev8v0uGx/RZyJqyZ4sNi7Q6/4=";
          };
          swift-system = pkgs.fetchFromGitHub {
            owner = "apple";
            repo = "swift-system";
            rev = "7c6ad0fc39d0763e0b699210e4124afd5041c5df";
            hash = "sha256-bfxm2WS+4qcgSzheWTvRloDAIIIHzPZ8SaAZq9bWmSc=";
          };

          workspaceState = builtins.toJSON {
            object = {
              artifacts = [ ];
              dependencies = [
                {
                  basedOn = null;
                  packageRef = {
                    identity = "swift-argument-parser";
                    kind = "remoteSourceControl";
                    location = "https://github.com/apple/swift-argument-parser.git";
                    name = "swift-argument-parser";
                  };
                  state = {
                    checkoutState = {
                      revision = "626b5b7b2f45e1b0b1c6f4a309296d1d21d7311b";
                      version = "1.7.1";
                    };
                    name = "sourceControlCheckout";
                  };
                  subpath = "swift-argument-parser";
                }
                {
                  basedOn = null;
                  packageRef = {
                    identity = "swift-subprocess";
                    kind = "remoteSourceControl";
                    location = "https://github.com/swiftlang/swift-subprocess.git";
                    name = "Subprocess";
                  };
                  state = {
                    checkoutState = {
                      revision = "13d087685b95d64d6aac9b94500d347bbe84c39b";
                      version = "0.4.0";
                    };
                    name = "sourceControlCheckout";
                  };
                  subpath = "swift-subprocess";
                }
                {
                  basedOn = null;
                  packageRef = {
                    identity = "swift-system";
                    kind = "remoteSourceControl";
                    location = "https://github.com/apple/swift-system";
                    name = "swift-system";
                  };
                  state = {
                    checkoutState = {
                      revision = "7c6ad0fc39d0763e0b699210e4124afd5041c5df";
                      version = "1.6.4";
                    };
                    name = "sourceControlCheckout";
                  };
                  subpath = "swift-system";
                }
              ];
              prebuilts = [ ];
            };
            version = 7;
          };
        in
        {
          default = self.packages.${system}.pscht;

          pscht = pkgs.stdenvNoCC.mkDerivation {
            pname = "pscht";
            version = "0.1.0";

            src = pkgs.lib.cleanSource ./.;

            # Needs Xcode toolchain (Swift 6.3 not in nixpkgs)
            __noChroot = true;

            nativeBuildInputs = [ pkgs.xcbuild ];

            DEVELOPER_DIR = "/Applications/Xcode.app/Contents/Developer";
            SDKROOT = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";

            configurePhase = ''
              runHook preConfigure

              export HOME=$(mktemp -d)

              mkdir -p .build/checkouts
              ln -s ${swift-argument-parser} .build/checkouts/swift-argument-parser
              ln -s ${swift-subprocess} .build/checkouts/swift-subprocess
              ln -s ${swift-system} .build/checkouts/swift-system

              cat > .build/workspace-state.json << 'WSEOF'
              ${workspaceState}
              WSEOF

              runHook postConfigure
            '';

            buildPhase = ''
              runHook preBuild
              xcrun swift build -c release --disable-sandbox
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall

              mkdir -p $out/bin $out/share/pscht
              cp "$(xcrun swift build -c release --disable-sandbox --show-bin-path)/pscht" $out/bin/pscht-unsigned
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
        in
        {
          default = pkgs.mkShell {
            buildInputs = [ ];
          };
        }
      );
    };
}
