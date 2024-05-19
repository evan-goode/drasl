{
  description = "Self-hosted API server for Minecraft";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-23.11";
    buildNodeModules = {
      url = "github:adisbladis/buildNodeModules";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    buildNodeModules,
  }: let
    version = "1.1.0";

    # nodejs_20 is currently broken on Darwin
    supportedSystems = ["x86_64-linux" "aarch64-linux"];
    # supportedSystems = ["x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"];

    # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

    nixpkgsFor = forAllSystems (system: import nixpkgs {inherit system;});
    nixpkgsCross =
      forAllSystems (localSystem:
        forAllSystems (crossSystem: import nixpkgs {inherit localSystem crossSystem;}));
  in {
    packages = forAllSystems (system: let
      buildDrasl = pkgs: let
        nodejs = pkgs.nodejs_20;
        nodeModules = buildNodeModules.lib.${system}.buildNodeModules {
          inherit nodejs;
          packageRoot = ./.;
        };
      in
        pkgs.buildGoModule {
          pname = "drasl";
          inherit version;
          src = ./.;

          # Update whenever Go dependencies change
          vendorHash = "sha256-4AwUwDClrYp4jAqqMex38ElmbZwj5BY7LNmcddfV/ro=";

          outputs = ["out"];

          preConfigure = ''
            substituteInPlace build_config.go --replace "\"/usr/share/drasl\"" "\"$out/share/drasl\""
          '';

          nativeBuildInputs = [nodejs];

          preBuild = ''
            ln -s ${nodeModules}/node_modules node_modules
            node esbuild.config.js
          '';

          postInstall = ''
            mkdir -p "$out/share/drasl"
            cp -R ./{assets,view,public} "$out/share/drasl"
          '';
        };

      buildOCIImage = pkgs:
        pkgs.dockerTools.buildLayeredImage {
          name = "unmojang/drasl";
          contents = with pkgs; [cacert];
          config.Cmd = ["${buildDrasl pkgs}/bin/drasl"];
        };
    in rec {
      drasl = buildDrasl nixpkgsFor.${system};

      drasl-cross-x86_64-linux = buildDrasl nixpkgsCross.${system}.x86_64-linux;
      # drasl-cross-x86_64-darwin = buildDrasl nixpkgsCross.${system}.x86_64-darwin;
      drasl-cross-aarch64-linux = buildDrasl nixpkgsCross.${system}.aarch64-linux;
      # drasl-cross-aarch64-darwin = buildDrasl nixpkgsCross.${system}.aarch64-darwin;

      oci = buildOCIImage nixpkgsFor.${system};

      oci-cross-x86_64-linux = buildOCIImage nixpkgsCross.${system}.x86_64-linux;
      # oci-cross-x86_64-darwin = buildOCIImage nixpkgsCross.${system}.x86_64-darwin;
      oci-cross-aarch64-linux = buildOCIImage nixpkgsCross.${system}.aarch64-linux;
      # oci-cross-aarch64-darwin = buildOCIImage nixpkgsCross.${system}.aarch64-darwin;
    });

    nixosModules.drasl = {
      config,
      lib,
      pkgs,
      ...
    }:
      with lib; let
        cfg = config.services.drasl;
        format = pkgs.formats.toml {};
      in {
        options.services.drasl = {
          enable = mkEnableOption (lib.mdDoc ''drasl'');
          settings = mkOption {
            type = format.type;
            default = {};
            description = lib.mdDoc ''
              config.toml for drasl
            '';
          };
        };
        config = mkIf cfg.enable {
          systemd.services.drasl = {
            description = "drasl";
            wantedBy = ["multi-user.target"];

            serviceConfig = let
              pkg = self.defaultPackage.${pkgs.system};
              config = format.generate "config.toml" cfg.settings;
            in {
              ExecStart = "${pkg}/bin/drasl -config ${config}";
              DynamicUser = true;
              StateDirectory = "drasl";
              Restart = "always";
            };
          };
        };
      };

    devShells = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      default = pkgs.mkShell {
        # https://github.com/go-delve/delve/issues/3085
        hardeningDisable = ["fortify"];
        buildInputs = with pkgs; [
          alejandra
          delve
          go
          go-tools
          golangci-lint
          gopls
          gore
          gotools
          nodejs
          pre-commit
          sqlite-interactive
        ];
      };
    });

    defaultPackage = forAllSystems (system: self.packages.${system}.drasl);
  };
}
