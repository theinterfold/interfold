// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use risc0_build::{
    embed_methods_with_options, DockerOptionsBuilder, GuestListEntry, GuestOptionsBuilder,
};
use risc0_build_ethereum::generate_solidity_files;

// Paths where the generated Solidity files will be written.
const SOLIDITY_IMAGE_ID_PATH: &str = "../contracts/ImageID.sol";
const SOLIDITY_ELF_PATH: &str = "../tests/Elf.sol";

/// Reports whether the reproducible Docker guest build is selected.
///
/// The variable is read for its value, not its presence, so `RISC0_USE_DOCKER=0` selects the
/// local build.
fn use_docker() -> bool {
    matches!(
        env::var("RISC0_USE_DOCKER").unwrap_or_default().as_str(),
        "1" | "true" | "TRUE" | "yes" | "YES"
    )
}

/// Builds and returns the pinned guest-builder image tag.
///
/// risc0-build generates its own Dockerfile. Its default image has the wrong Rust version for the
/// pinned fhe.rs dependency and does not contain `protoc`. Build the small checked-in layer first,
/// then tell risc0-build to use it for the deterministic guest build.
fn guest_builder_tag(support_dir: &Path) -> String {
    let dockerfile = support_dir.join("methods/guest-builder.Dockerfile");
    println!("cargo:rerun-if-changed={}", dockerfile.display());

    let source = fs::read_to_string(&dockerfile).unwrap_or_else(|e| {
        panic!(
            "cannot read {} to resolve the guest toolchain: {e}",
            dockerfile.display()
        )
    });

    let toolchain = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("ARG RISC0_TOOLCHAIN="))
        .unwrap_or_else(|| panic!("no ARG RISC0_TOOLCHAIN in {}", dockerfile.display()))
        .trim();

    assert!(
        !toolchain.is_empty(),
        "ARG RISC0_TOOLCHAIN in {} is empty",
        dockerfile.display()
    );

    let tag = format!("interfold-r0.{toolchain}-protoc-v1");
    let image = format!("risczero/risc0-guest-builder:{tag}");
    let status = Command::new("docker")
        .args([
            "build",
            "--platform",
            "linux/amd64",
            "--load",
            "--provenance=false",
            "--tag",
            &image,
            "--file",
        ])
        .arg(&dockerfile)
        .arg(support_dir)
        .status()
        .unwrap_or_else(|e| panic!("cannot start Docker to build {image}: {e}"));
    assert!(
        status.success(),
        "failed to build the pinned RISC Zero guest-builder image {image}"
    );

    tag
}

/// Copies each Docker-built ELF to the path used by the upload command.
fn copy_docker_elves_to_release(guests: &[GuestListEntry]) {
    for guest in guests {
        let source = Path::new(guest.path.as_ref());
        let docker_dir = source.parent().unwrap_or_else(|| {
            panic!(
                "Docker guest ELF has no parent directory: {}",
                source.display()
            )
        });
        if docker_dir.file_name().and_then(|name| name.to_str()) != Some("docker") {
            panic!(
                "Docker guest ELF is outside the Docker profile: {}",
                source.display()
            );
        }

        let profile_root = docker_dir.parent().unwrap_or_else(|| {
            panic!(
                "Docker guest profile has no parent: {}",
                docker_dir.display()
            )
        });
        let release_dir = profile_root.join("release");
        fs::create_dir_all(&release_dir).unwrap_or_else(|e| {
            panic!(
                "cannot create upload artifact directory {}: {e}",
                release_dir.display()
            )
        });

        let file_name = source
            .file_name()
            .unwrap_or_else(|| panic!("Docker guest ELF has no file name: {}", source.display()));
        let destination = release_dir.join(file_name);
        fs::copy(source, &destination).unwrap_or_else(|e| {
            panic!(
                "cannot copy Docker guest ELF from {} to {}: {e}",
                source.display(),
                destination.display()
            )
        });
    }
}

fn main() {
    // Builds can be made deterministic, and thereby reproducible, by using Docker to build the
    // guest. Set RISC0_USE_DOCKER to 1 (or true) to select the reproducible Docker build. Any
    // other value, and an unset variable, select the local build.
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let reproducible = use_docker();
    let mut builder = GuestOptionsBuilder::default();
    if reproducible {
        let support_dir = manifest_dir.join("../");
        // The official guest-builder image is linux/amd64. Set the platform for the nested Docker
        // build as well, so Apple Silicon developers produce the same ELF as CI.
        env::set_var("DOCKER_DEFAULT_PLATFORM", "linux/amd64");
        let docker_options = DockerOptionsBuilder::default()
            .root_dir(support_dir.clone())
            .docker_container_tag(guest_builder_tag(&support_dir))
            .build()
            .unwrap();
        builder.use_docker(docker_options);
    }
    let guest_options = builder.build().unwrap();

    // Generate Rust source files for the methods crate.
    let guests = embed_methods_with_options(HashMap::from([("guests", guest_options)]));

    if reproducible {
        copy_docker_elves_to_release(&guests);
    }

    // A native guest build is useful for local development, but its image ID can vary with the
    // host toolchain. Never let such a build replace the production trust anchor checked into the
    // repository. Only the pinned Docker build may update ImageID.sol and Elf.sol.
    if reproducible && std::env::var("SKIP_SOLIDITY").unwrap_or_default() != "1" {
        // Generate Solidity source files for use with Forge.
        let solidity_opts = risc0_build_ethereum::Options::default()
            .with_image_id_sol_path(SOLIDITY_IMAGE_ID_PATH)
            .with_elf_sol_path(SOLIDITY_ELF_PATH);
        generate_solidity_files(guests.as_slice(), &solidity_opts).unwrap();
    } else if !reproducible {
        println!(
            "cargo:warning=Skipping Solidity codegen for a non-reproducible native guest build"
        );
    } else {
        println!("cargo:warning=Skipping Solidity codegen (SKIP_SOLIDITY set)");
    }
}
