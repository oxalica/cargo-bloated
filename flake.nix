rec {
  description = "Find out what takes most of the space in your executable, more accurately";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      eachSystem = lib.genAttrs (lib.systems.flakeExposed);
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          date = self.lastModifiedDate;
          version = "0-unstable-${lib.substring 0 4 date}-${lib.substring 4 2 date}-${lib.substring 6 2 date}";
        in
        rec {
          default = cargo-bloated;
          cargo-bloated =
            with pkgs;
            rustPlatform.buildRustPackage rec {
              pname = "cargo-bloated";
              inherit version;
              src = self;
              cargoLock.lockFile = ./Cargo.lock;

              meta = {
                inherit description;
                homepage = "https://github.com/oxalica/cargo-bloated";
                license = [
                  lib.licenses.mit
                  # OR
                  lib.licenses.asl20
                ];
                platforms = lib.platforms.linux;
              };
            };
        }
      );
    };
}
