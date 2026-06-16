{
  description = "Interfold";
  nixConfig = {
    extra-substituters = ["https://interfold.cachix.org"];
    extra-trusted-public-keys = ["interfold.cachix.org-1:B5SynR85iX/TRueDpZu4dh1xVR8lNfKoAaVWZkux1ss="];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: let
    # define the version hashes. everytime we change dependencies these need to change
    noirHash = "sha256-RoeWaqgFwr8A4HAlu5DzuxrNrexMolIZG14fHQA0KmM=";
    fheHash = "sha256-dS8LcKDI/D9ycsRXbQnMVkUc2ymFBFL8kDrEtRGuHNI=";
    vfsHash = "sha256-+d8RFk7UgOXDCE/LizCTV+UX/Xm/1mYWrR7W0l6mAl8=";
    # bb version + checksums driven from versions.json
    versionsJson = builtins.fromJSON (builtins.readFile ./crates/zk-prover/versions.json);
    bbVersion = versionsJson.required_bb_version;
    bbHashes = versionsJson.bb_checksums;
  in
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };
      noirSrc = pkgs.fetchFromGitHub {
        owner = "noir-lang";
        repo = "noir";
        rev = "v1.0.0-beta.16";
        hash = noirHash;
      };
      bbPlatform =
        if pkgs.stdenv.isLinux
        then
          if pkgs.stdenv.isAarch64
          then "arm64-linux"
          else "amd64-linux"
        else if pkgs.stdenv.isDarwin
        then
          if pkgs.stdenv.isAarch64
          then "arm64-darwin"
          else "amd64-darwin"
        else throw "Unsupported platform";
      bbBin = pkgs.stdenv.mkDerivation {
        pname = "barretenberg";
        version = bbVersion;
        src = pkgs.fetchurl {
          url = "https://github.com/AztecProtocol/aztec-packages/releases/download/v${bbVersion}/barretenberg-${bbPlatform}.tar.gz";
          sha256 = bbHashes.${bbPlatform};
        };
        nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [pkgs.autoPatchelfHook];
        buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [pkgs.stdenv.cc.cc.lib];
        sourceRoot = ".";
        installPhase = ''
          mkdir -p $out/bin
          install -D -m755 bb $out/bin/bb
        '';
        meta = {
          description = "Barretenberg proving system";
          homepage = "https://github.com/AztecProtocol/aztec-packages";
        };
      };
      bb =
        if pkgs.stdenv.isLinux
        then
          pkgs.buildFHSEnv {
            name = "bb";
            targetPkgs = p: [bbBin p.stdenv.cc.cc.lib];
            runScript = "${bbBin}/bin/bb";
          }
        else bbBin;
      wrapped-bb =
        if pkgs.stdenv.isLinux
        then
          pkgs.writeShellScriptBin "bb" ''
            exec ${pkgs.steam-run}/bin/steam-run ${bb}/bin/bb "$@"
          ''
        else bb;
      e3-cli = pkgs.rustPlatform.buildRustPackage {
        pname = "e3-cli";
        version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
        src = ./.;
        GIT_SHA = self.rev or self.dirtyRev or "unknown";
        GIT_COMMIT = "unknown";
        GIT_DIRTY = "false";
        preBuild = ''
          for d in $(find /build -type d -name 'noirc_driver*'); do
            if [ -d "$d/src" ]; then
              cp -r ${noirSrc}/noir_stdlib "$d/../../noir_stdlib"
            fi
          done
          export HOME=$(mktemp -d)
          git config --global user.email "nix@nix"
          git config --global user.name "nix"
          git init
          git add -A
          git commit -m "nix build" --allow-empty
        '';
        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = builtins.listToAttrs (
            map (name: {
              inherit name;
              value = noirHash;
            }) [
              "acir-1.0.0-beta.16"
              "acir_field-1.0.0-beta.16"
              "acvm-1.0.0-beta.16"
              "acvm_blackbox_solver-1.0.0-beta.16"
              "bn254_blackbox_solver-1.0.0-beta.16"
              "brillig-1.0.0-beta.16"
              "brillig_vm-1.0.0-beta.16"
              "fm-1.0.0-beta.16"
              "iter-extended-1.0.0-beta.16"
              "nargo-1.0.0-beta.16"
              "noir_greybox_fuzzer-1.0.0-beta.16"
              "noir_protobuf-1.0.0-beta.16"
              "noirc_abi-1.0.0-beta.16"
              "noirc_arena-1.0.0-beta.16"
              "noirc_artifacts-1.0.0-beta.16"
              "noirc_driver-1.0.0-beta.16"
              "noirc_errors-1.0.0-beta.16"
              "noirc_evaluator-1.0.0-beta.16"
              "noirc_frontend-1.0.0-beta.16"
              "noirc_printable_type-1.0.0-beta.16"
              "noirc_span-1.0.0-beta.16"
            ]
            ++ map (name: {
              inherit name;
              value = fheHash;
            }) [
              "fhe-0.2.0"
              "fhe-math-0.2.0"
              "fhe-traits-0.1.1"
              "fhe-util-0.1.1"
            ]
            ++ map (name: {
              inherit name;
              value = vfsHash;
            }) [
              "vfs-0.12.1"
            ]
          );
        };
        buildAndTestSubdir = "crates/cli";
        nativeBuildInputs = [
          pkgs.pkg-config
          pkgs.git
          pkgs.pnpm
          pkgs.nodejs
          pkgs.jq
          pkgs.solc
        ];
        buildInputs = [
          pkgs.openssl
        ];
        meta = {
          description = "e3 CLI";
          license = pkgs.lib.licenses.lgpl3Only;
        };
      };
    in {
      packages.default = e3-cli;
      packages.cli = e3-cli;
      packages.bb = wrapped-bb;
      devShells.default = pkgs.mkShell {
        packages = [
          e3-cli
          wrapped-bb
        ];
        shellHook = ''
          export E3_CUSTOM_BB="${wrapped-bb}/bin/bb"
        '';
      };
    });
}
