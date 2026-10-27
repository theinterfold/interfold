// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk (Barretenberg client IVC) types and the C3 Chonk accumulator.
//!
//! **C3 over Chonk.** A Chonk stack is an app and three kernels. The app (`c3_chonk_app`) verifies
//! a batch of C3 proofs and writes their rows; each kernel verifies the circuit before it and
//! passes the rows on. Inside a Mega app an UltraHonk verification costs about 12K gates against
//! about 700K in an UltraHonk circuit, which is what makes a stack cheaper than folding the proofs one UltraHonk step at a time.
//!
//! **Keys.** Every key a stage verifies against is a witness, so each stage appends its key's hash
//! to the data it passes on: the app the C3 leaf key, the init kernel the app key, the tail kernel
//! the init key, the hiding kernel the tail key. `c3_chonk_tube` verifies the stack's Chonk proof
//! and adds the Chonk key. The consumer above pins every hash against the anchored VK tree, so a
//! stack built from other circuits is rejected.
//!
//! **Rollups.** The tube and `c3_chonk_accumulate` are rollup proofs: each carries an IPA claim,
//! the accumulate step merges two into one, and `c3ab_fold` closes both chains' claims once.

use crate::configs::default::T;

/// A Mega verification key and its hash, as a kernel verifies the circuit before it.
pub global MEGA_VK_LENGTH: u32 = 163;
/// The hiding kernel's Chonk key, as `c3_chonk_tube` verifies the stack.
pub global CHONK_VK_LENGTH: u32 = 115;
/// A Chonk proof without its public inputs.
pub global CHONK_PROOF_LENGTH: u32 = 1270;

pub global PROOF_TYPE_OINK: u32 = 1;
pub global PROOF_TYPE_HN_FINAL: u32 = 7;
pub global PROOF_TYPE_HN_TAIL: u32 = 8;
pub global PROOF_TYPE_CHONK: u32 = 9;

pub struct MegaVerificationKey {
    pub key: [Field; MEGA_VK_LENGTH],
    pub hash: Field,
}

/// Leaves one `c3_chonk_app` verifies. Each stack adds a tube and an accumulate proof, so larger
/// stacks are faster, but the stack's ECCVM trace grows with them: bb 5.2.0 proves 24 and rejects
/// 28 (ECCVM_FIXED_SIZE 2^15).
pub global C3_CHONK_LEAVES: u32 = 24;

/// Key hashes a tube or accumulate proof exposes before the rows: its own key, the tube key, the
/// stack's Chonk key, then the C3 leaf, app, init kernel and tail kernel keys.
pub global C3_CHONK_KEYS: u32 = 7;
pub global C3_CHONK_OWN_KEY: u32 = 0;
pub global C3_CHONK_TUBE_KEY: u32 = 1;

/// C6 proofs one `c6_chonk_app` verifies: a decryption's whole chain, one per slot, so one stack
/// holds it while `T + 1` stays under the ECCVM bound of `C3_CHONK_LEAVES`-sized stacks.
pub global C6_CHONK_LEAVES: u32 = T + 1;
/// Data a C6 Chonk stack carries: the two domain limbs, then the sk, esm, ct and d columns.
pub global C6_CHONK_DATA_LEN: u32 = 2 + 4 * (T + 1);

/// Merges two disjoint row sets. A slot may be filled on at most one side.
pub fn merge_rows<let ROWS: u32>(left: [Field; ROWS], right: [Field; ROWS]) -> [Field; ROWS] {
    let mut merged = [0; ROWS];
    for i in 0..ROWS {
        assert((left[i] == 0) | (right[i] == 0), "slot filled on both sides");
        merged[i] = left[i] + right[i];
    }
    merged
}

#[test]
fn disjoint_rows_merge() {
    assert(merge_rows([1, 0, 0, 4], [0, 2, 0, 0]) == [1, 2, 0, 4]);
}

#[test(should_fail_with = "slot filled on both sides")]
fn overlapping_rows_are_rejected() {
    let _ = merge_rows([1, 0], [1, 0]);
}
