// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=FORCE_BUILD");
    println!("cargo:rerun-if-env-changed=E3_ZK_PROVER_SKIP_FIXTURE_BUILD");
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-env-changed=E3_CIRCUITS_ARCHIVE_SHA256");
    let archive_digest = std::env::var("E3_CIRCUITS_ARCHIVE_SHA256").unwrap_or_default();
    assert!(
        archive_digest.is_empty()
            || (archive_digest.len() == 64
                && archive_digest.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "E3_CIRCUITS_ARCHIVE_SHA256 must be a SHA-256 digest (64 hexadecimal characters)"
    );
    println!(
        "cargo:rustc-env=E3_CIRCUITS_ARCHIVE_SHA256={}",
        archive_digest.to_ascii_lowercase()
    );

    if std::env::var("E3_ZK_PROVER_SKIP_FIXTURE_BUILD").as_deref() == Ok("1") {
        return;
    }

    assert!(Command::new("bash")
        .arg("./scripts/build_fixtures.sh")
        .status()
        .unwrap()
        .success());

    println!("cargo:rerun-if-changed=./scripts/build_fixtures.sh");
}
