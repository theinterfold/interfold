// SPDX-License-Identifier: LGPL-3.0-only
//
//! r130 regression: fixture-bootstrap nested-cargo deadlock (r127 n2, composite fix).
//!
//! Deadlock mechanism (r127 RAN diagnosis): `crates/zk-prover/build.rs` runs
//! `scripts/build_fixtures.sh`, which — when the 3 recursive_aggregation fold
//! artifacts (c3_fold / c6_fold / c6_fold_kernel json) are missing from a lean
//! checkout — previously invoked `pnpm build:circuits`, whose
//! `regenerateParityMatrices()` ran a NESTED `cargo run --release --bin
//! generate_parity_matrices` in the SAME target dir while the OUTER `cargo
//! test`/`cargo build` process still held `target/release/.cargo-lock`.
//! Outer waits on build.rs; build.rs waits on pnpm; pnpm waits on the nested
//! cargo; the nested cargo waits on the outer lock. Deadlock: the first
//! `cargo test` (or `cargo build`) of the zk-prover crate on a lean checkout
//! could NEVER complete (r127 observed this via a second outer job hang).
//!
//! Composite fix under test (this round):
//!   FIX1: `scripts/build-circuits.ts` gains `--skip-regen-parity`;
//!         `regenerateParityMatrices()` early-returns, trusting the COMMITTED
//!         on-disk parity matrices (they are git-tracked literals under
//!         circuits/lib/src/configs/committee/<committee>/parity_{insecure,secure}.nr;
//!         the only mutation path documented is a top-level manual regen).
//!   FIX2: `crates/zk-prover/scripts/build_fixtures.sh` passes
//!         `--skip-regen-parity` to build:circuits from inside the outer cargo.
//!   FIX3: `scripts/build-circuits.ts` classifies Noir `type = "lib"` packages
//!         (e.g. c3_fold_batch_lib) as dep-only and skips them — `nargo
//!         compile` RC 0 emits no artifact for a lib, which the
//!         artifact-existence check would reject.
//!
//! RAN proof this leg (see poc/r130/RESULT.txt + v5_run.log):
//!   (a) the EXACT deadlocking call pattern still deadlocks TODAY with a
//!       pre-fix-shaped invocation (nested `cargo run` under an outer cargo in
//!       the same target dir) — the mechanism is alive bash-verified; the fix
//!       is the removal of that call, and
//!   (b) the SAME dead context (an outer -x flock on target/release/.cargo-lock,
//!       the r127 n2 shape) now drives a lean stage tree missing all required
//!       fold artifacts through the FIXED bootstrap: build_fixtures.sh ->
//!       `pnpm build:circuits --skip-regen-parity` -> 36/36 circuits compile
//!       (incl. the 4 deleted artifacts) -> artifacts land BYTE-IDENTICAL to
//!       the r111/r115-anchored SHAs -> RC 0 in 180 s, with ZERO nested
//!       `cargo` processes spawned during the whole run (PATH cargo-trap
//!       observable). No hang.

#[test]
fn r130_bootstrap_skips_nested_cargo_parity_regen() {
    // The test binary runs with cwd = crate root, but the repo paths the
    // preload fix touches are workspace-root-relative — resolve from the
    // manifest dir (the same way build.rs reaches the same script).
    let root = std::path::Path::new(std::env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let sh = std::fs::read_to_string(root.join("crates/zk-prover/scripts/build_fixtures.sh"))
        .unwrap_or_else(|e| panic!("crates/zk-prover/scripts/build_fixtures.sh unreadable: {e}"));
    let ts = std::fs::read_to_string(root.join("scripts/build-circuits.ts"))
        .unwrap_or_else(|e| panic!("scripts/build-circuits.ts unreadable: {e}"));

    // FIX2: the in-cargo bootstrap must pass the no-nested-cargo flag.
    assert!(
        sh.contains("--skip-regen-parity"),
        "build_fixtures.sh lost --skip-regen-parity: the in-cargo fixture bootstrap \
         would deadlock on target/.cargo-lock again (r127 n2 / r130)"
    );

    // FIX1: the skip hook exists in the builder.
    assert!(
        ts.contains("skipRegenParity"),
        "build-circuits.ts lost the skipRegenParity hook: the parity-matrices \
         regen path has no in-cargo escape hatch (r130 FIX1)"
    );

    // FIX3: lib-only Noir packages are classified and skipped.
    assert!(
        ts.contains("isLibOnly"),
        "build-circuits.ts lost the isLibOnly classifier: a lib-only package \
         (e.g. c3_fold_batch_lib) would re-fail the build with \
         'compiled artifact not found' (r130 FIX3)"
    );

    // Negative core: the nested `cargo run` call site still exists, and the
    // skip-guard PRECEDES it (a guardless nested-cargo call anywhere in the
    // in-cargo bootstrap chain resurrects the deadlock class). Locate by the
    // execSync that spawns it, not by counting doc-comment mentions.
    let regen_call = ts
        .find("execSync(`cargo run")
        .expect("nested parity-matrix regen call missing");
    let try_guard = ts
        .find("if (this.options.skipRegenParity)")
        .expect("skip-guard missing");
    assert!(
        try_guard < regen_call,
        "skip-guard does not precede the nested `cargo run` call: the guard is \
         ineffective (r130 FIX1 invalidated)"
    );

    println!("PASS r130: bootstrap chain carries --skip-regen-parity (FIX1+FIX2+FIX3)");
}