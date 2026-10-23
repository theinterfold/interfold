{
  description = "Rust + WASM development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      rustToolchain = pkgs.rust-bin.stable."1.91.1".default.override {
        targets = ["wasm32-unknown-unknown"];
      };
    in {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          openssl
          pkg-config
          rustToolchain
          wasm-pack
          nodejs
          nodePackages.pnpm
          rust-analyzer
        ];
      };
    });
}
