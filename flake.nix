{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };

      craneLib = crane.lib."${system}";

      src = craneLib.cleanCargoSource ./.;
      cargoArtifacts = craneLib.buildDepsOnly { inherit src; };

    in {
      packages."${system}" = rec {
        poser = craneLib.buildPackage {
          inherit src cargoArtifacts;
        };

        poser-container = pkgs.callPackage ({ dockerTools, writeScript }:
          dockerTools.buildLayeredImage {
            name = "poser";

            fakeRootCommands = ''
              ${dockerTools.shadowSetup}
              useradd --system --user-group --create-home poser
            '';
            enableFakechroot = true;

            config = {
              Cmd = [ "${pkgs.poser}/bin/poser" ];
              User = "poser";
              ExposedPorts = { "8080/tcp" = {}; };
            };
          }
        ) {};

        default = poser;
      };

      checks."${system}" = {
        poser-tests = craneLib.cargoTest {
          inherit src cargoArtifacts;
        };

        poser-clippy = craneLib.cargoClippy {
          inherit src cargoArtifacts;

          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
        };

        poser-fmt = craneLib.cargoFmt {
          inherit src;
        };
      };

      overlays.default = final: prev: { } // self.packages."${system}";

      devShells."${system}".default = pkgs.mkShell {
        nativeBuildInputs = [
          pkgs.cargo
          pkgs.rustc
        ];
      };
    };
}
