{
  description = "pscht - Store secrets with biometric (macOS) or TPM2 (Linux) protection";

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
        "x86_64-linux"
        "aarch64-linux"
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

          darwinBundle = mkSwiftPackage {
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
              BUNDLE="$out/Applications/pscht.app/Contents"
              mkdir -p "$BUNDLE/MacOS"
              mv $out/bin/pscht "$BUNDLE/MacOS/pscht"
              cp ${./Info.plist} "$BUNDLE/Info.plist"

              cat > $out/bin/pscht-sign << 'SIGN'
#!/bin/bash
set -euo pipefail
BUNDLE="$1"
IDENTITY="$2"
PROFILE="$3"

cp "$PROFILE" "$BUNDLE/Contents/embedded.provisionprofile"

DECODED=$(mktemp)
ENTITLEMENTS=$(mktemp)
trap 'rm -f "$DECODED" "$ENTITLEMENTS"' EXIT
/usr/bin/security cms -D -i "$PROFILE" > "$DECODED"
/usr/libexec/PlistBuddy -c "Print :Entitlements" -x "$DECODED" > "$ENTITLEMENTS"

/usr/bin/codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS" "$BUNDLE"
SIGN
              chmod +x $out/bin/pscht-sign

              cat > $out/bin/pscht << 'WRAPPER'
#!/bin/bash
PSCHT_APP="$HOME/.local/share/pscht/pscht.app"
exec "$PSCHT_APP/Contents/MacOS/pscht" "$@"
WRAPPER
              chmod +x $out/bin/pscht
            '';

            meta = {
              description = "pscht - macOS Keychain + Touch ID secret manager";
              platforms = pkgs.lib.platforms.darwin;
              mainProgram = "pscht";
            };
          };

          linuxPackage =
            let
              gccCxx = "${pkgs.stdenv.cc.cc}/include/c++/${pkgs.stdenv.cc.cc.version}";
              gccCxxTriple = "${gccCxx}/${pkgs.stdenv.hostPlatform.config}";
            in
            mkSwiftPackage {
              pname = "pscht";
              version = "0.1.0";
              src = pkgs.lib.cleanSource ./.;
              swift = swiftix.packages.${system}.swift-6_3;
              swiftpmGenerated = swiftpm2nixHelpers ./nix;
              executableName = "pscht";

              nativeBuildInputs = [ pkgs.makeWrapper pkgs.pkg-config ];
              buildInputs = [ pkgs.libargon2 ];

              # swiftix's configurePhase sets C_INCLUDE_PATH but not
              # CPLUS_INCLUDE_PATH — fine for pure-C/Swift packages, but
              # swift-crypto ships BoringSSL C++ code that needs the libstdc++
              # include paths to resolve <stdlib.h>, <memory>, etc.
              postConfigure = ''
                export CPLUS_INCLUDE_PATH="${gccCxx}:${gccCxxTriple}:${pkgs.stdenv.cc.libc.dev}/include''${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"
              '';

              # Wrap pscht so tpm2-tools is always on PATH regardless of how
              # the user launched the binary. Users don't need to add anything
              # to their own PATH for the subprocess calls to succeed.
              postInstall = ''
                wrapProgram $out/bin/pscht \
                  --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.tpm2-tools ]}
              '';

              meta = {
                description = "pscht - TPM2-sealed secret manager";
                platforms = pkgs.lib.platforms.linux;
                mainProgram = "pscht";
              };
            };

          pschtPackage =
            if pkgs.stdenv.hostPlatform.isDarwin
            then darwinBundle
            else linuxPackage;
        in
        {
          default = pschtPackage;
          pscht = pschtPackage;
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
          isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
          isLinux = pkgs.stdenv.hostPlatform.isLinux;

          effectiveBackend =
            if cfg.backend == "auto"
            then (if isDarwin then "keychain" else "tpm2")
            else cfg.backend;

          tomlFormat = pkgs.formats.toml { };

          configToml = tomlFormat.generate "pscht-config.toml" (
            { backend = effectiveBackend; }
            // lib.optionalAttrs (cfg.dataDir != null) {
              paths = { data_dir = cfg.dataDir; };
            }
            // lib.optionalAttrs (effectiveBackend == "tpm2") {
              tpm2 = {
                mode = cfg.tpm2.mode;
                device = cfg.tpm2.device;
                pcrs = cfg.tpm2.pcrs;
                pin_prompt = cfg.tpm2.pinPrompt;
                argon2 = {
                  memory_kib = cfg.tpm2.argon2.memoryKiB;
                  iterations = cfg.tpm2.argon2.iterations;
                  parallelism = cfg.tpm2.argon2.parallelism;
                };
              };
            }
          );
        in
        {
          options.programs.pscht = {
            enable = lib.mkEnableOption "pscht - secret manager";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${system}.pscht;
              description = "The pscht package to install.";
            };

            backend = lib.mkOption {
              type = lib.types.enum [ "keychain" "tpm2" "auto" ];
              default = "auto";
              description = ''
                Which secret backend to use.
                `auto` picks keychain on macOS and tpm2 on Linux.
              '';
            };

            dataDir = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/home/alice/.local/share/pscht";
              description = ''
                Override the data directory. Defaults to
                `$XDG_DATA_HOME/pscht` (typically `~/.local/share/pscht`).
              '';
            };

            tpm2 = {
              mode = lib.mkOption {
                type = lib.types.enum [ "pin" "presence" ];
                default = "pin";
                description = ''
                  PIN: interactive PIN, TPM enforces hardware lockout.
                  Presence: no PIN (EC2/servers).
                '';
              };
              device = lib.mkOption {
                type = lib.types.str;
                default = "/dev/tpmrm0";
                description = ''
                  TPM device or TCTI URL. Plain paths are mapped to
                  `device:<path>`; strings containing `:` are passed through
                  as-is (e.g. `swtpm:path=/run/my/sock`).
                '';
              };
              pcrs = lib.mkOption {
                type = lib.types.listOf lib.types.ints.unsigned;
                default = [ ];
                example = [ 7 ];
                description = ''
                  PCRs to bind the sealed object to. Empty list = unbound.
                  Binding to non-empty PCRs causes the vault to become
                  unreadable after any system change that re-measures those
                  PCRs (kernel updates, bootloader changes, etc.).
                '';
              };
              pinPrompt = lib.mkOption {
                type = lib.types.enum [ "tty" "systemd" ];
                default = "tty";
                description = "How to prompt for the PIN.";
              };
              argon2 = {
                memoryKiB = lib.mkOption {
                  type = lib.types.ints.positive;
                  default = 262144;
                  description = "Argon2id memory cost (kibibytes).";
                };
                iterations = lib.mkOption {
                  type = lib.types.ints.positive;
                  default = 3;
                  description = "Argon2id iteration count.";
                };
                parallelism = lib.mkOption {
                  type = lib.types.ints.positive;
                  default = 1;
                  description = "Argon2id parallelism.";
                };
              };
            };

            signingIdentity = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "Apple Development: Your Name (TEAMID)";
              description = ''
                macOS only. Code signing identity for Keychain ACL access.
                If null, auto-detects the first available identity.
              '';
            };

            provisioningProfile = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                macOS only. Path to a provisioning profile for the dev.pscht
                App ID. Required for biometric keychain ACLs. Can be a sops
                secret path.
              '';
            };
          };

          config = lib.mkIf cfg.enable (lib.mkMerge [
            {
              home.packages = [ cfg.package ];
              xdg.configFile."fish/completions/pscht.fish".source =
                ./completions/pscht.fish;
              xdg.configFile."pscht/config.toml".source = configToml;
            }

            (lib.mkIf isDarwin {
              home.activation.pscht-codesign =
                lib.hm.dag.entryAfter [ "writeBoundary" ] ''
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

                  if [ -z "${cfg.provisioningProfile or ""}" ]; then
                    run echo "pscht: WARNING - no provisioningProfile configured, skipping signing"
                  elif [ -n "$IDENTITY" ]; then
                    rm -rf "$PSCHT_APP"
                    mkdir -p "$(dirname "$PSCHT_APP")"
                    cp -R "$SRC_BUNDLE" "$PSCHT_APP"
                    chmod -R u+w "$PSCHT_APP"

                    ${cfg.package}/bin/pscht-sign "$PSCHT_APP" "$IDENTITY" "${cfg.provisioningProfile or ""}"

                    run echo "pscht: signed app bundle with $IDENTITY"
                  else
                    run echo "pscht: WARNING - no codesigning identity found, biometrics will not work"
                  fi
                '';
            })

            (lib.mkIf isLinux {
              # On Linux the config.toml is the only state the module manages.
              # The vault itself (sealed.ctx, vault.enc, index.json) is
              # created by `pscht init` — sealing requires a live TPM,
              # which can't happen in a Nix build.
            })
          ]);
        };

      # NixOS module for system-wide install. Only meaningful on Linux.
      # Home-manager still owns per-user config.toml; this module handles
      # packaging + (optionally) the udev rules / tss group so /dev/tpmrm0
      # is reachable by unprivileged users.
      nixosModules.default = self.nixosModules.pscht;

      nixosModules.pscht =
        { lib, pkgs, config, ... }:
        let
          cfg = config.programs.pscht;
        in
        {
          options.programs.pscht = {
            enable = lib.mkEnableOption "pscht system-wide install";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.pscht;
              description = "The pscht package to install system-wide.";
            };
            enableTpmAccess = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Install udev rules that give members of the `tss` group
                read/write access to /dev/tpmrm0. Required for pscht to
                talk to the TPM without sudo.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            users.groups.tss = lib.mkIf cfg.enableTpmAccess { };

            services.udev.extraRules = lib.mkIf cfg.enableTpmAccess ''
              KERNEL=="tpm[0-9]*", MODE="0660", GROUP="tss"
              KERNEL=="tpmrm[0-9]*", MODE="0660", GROUP="tss"
            '';
          };
        };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          swift = swiftix.packages.${system}.swift-6_3;
          isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
        in
        {
          default = pkgs.mkShell {
            packages =
              [ swift ]
              ++ pkgs.lib.optionals isDarwin [ pkgs.apple-sdk_15 ]
              ++ pkgs.lib.optionals (!isDarwin) [
                # Note: no pkgs.stdenv.cc here. The swiftix toolchain ships
                # its own clang + a baked-in sysroot and a setup-hook that
                # points CC at it. Adding pkgs.stdenv.cc would override that
                # with gcc, which rejects Swift's clang-only flags like
                # -target and -fblocks.
                pkgs.tpm2-tools
                pkgs.swtpm
                pkgs.libargon2
                pkgs.pkg-config
              ];
            shellHook =
              if isDarwin then
                ''
                  export SDKROOT="${pkgs.apple-sdk_15}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
                ''
              else
                let
                  gccCxx = "${pkgs.stdenv.cc.cc}/include/c++/${pkgs.stdenv.cc.cc.version}";
                  gccCxxTriple = "${gccCxx}/${pkgs.stdenv.hostPlatform.config}";
                in
                ''
                  # mkShell's implicit stdenv sets CC=gcc via cc-wrapper's
                  # setup-hook, which runs after swiftix's setup-hook. Force
                  # CC to the Swift toolchain's clang so SwiftPM-driven C
                  # compilation accepts clang-only flags like -target and
                  # -fblocks.
                  export CC="${swift}/bin/clang"
                  export CXX="${swift}/bin/clang++"
                  # The Swift-bundled clang has no default header/library
                  # search paths on NixOS. Point it at nixpkgs' glibc so
                  # that `#include <sys/epoll.h>` etc. resolve when SwiftPM
                  # compiles C sources in packages like swift-system.
                  export C_INCLUDE_PATH="${pkgs.stdenv.cc.libc.dev}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
                  # swift-crypto's BoringSSL includes C++ stdlib headers like
                  # <memory>; add libstdc++'s include paths explicitly.
                  export CPLUS_INCLUDE_PATH="${gccCxx}:${gccCxxTriple}:${pkgs.stdenv.cc.libc.dev}/include''${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"
                  export LIBRARY_PATH="${pkgs.stdenv.cc.libc}/lib:${pkgs.stdenv.cc.cc.lib}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"
                '';
          };
        }
      );
    };
}
