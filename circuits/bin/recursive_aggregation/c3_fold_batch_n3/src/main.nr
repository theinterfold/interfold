// SPDX-License-Identifier: LGPL-3.0-only
//! I5 round 4.4: BATCHED NON-RECURSIVE c3 fold (wall-clock PoC, RAN, insecure-512,
//! minimum committee N=3 T=1, L=2 -> C3_SLOTS=6).
//! One circuit verifies LEAVES_COUNT inner ZK ShareEncryption proofs + ONE acc (kernel
//! genesis, non-ZK) proof and emits the post-fold accumulator public state.
//! Replaces the recursive chain `kernel + <LEAVES_COUNT-1> steps` (each step re-verifies
//! the prior fold proof). Serial wall is a reference, not the shipping path.
use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_FOLD_PUBLIC_LEN: u32 = 4 + (3 * C3_SLOTS);
pub global C3_FOLD_PREFIX_LEN: u32 = C3_FOLD_PUBLIC_LEN - (3 * C3_SLOTS);

pub global LEAVES_COUNT: u32 = 2;

/// Verify slot `slot` (a CONST compile-time value, unique per leaf) against the
/// genesis acc (asserts the slot was empty and writes the new commitments).
fn leaf3<let slot: u32>(
    ivk: UltraHonkVerificationKey,
    iprf: UltraHonkZKProof,
    c3pi: [Field; 3],
    ikh: Field,
    apk: [Field; C3_FOLD_PUBLIC_LEN],
) -> (Field, Field, Field) {
    verify_honk_proof(ivk, iprf, c3pi, ikh);
    assert(apk[C3_FOLD_PREFIX_LEN + slot] == 0, "slot pk empty");
    assert(apk[C3_FOLD_PREFIX_LEN + C3_SLOTS + slot] == 0, "slot msg empty");
    assert(apk[C3_FOLD_PREFIX_LEN + (2 * C3_SLOTS) + slot] == 0, "slot ct empty");
    (c3pi[0], c3pi[1], c3pi[2])
}

fn main(
    ivk0: UltraHonkVerificationKey,
    iprf0: UltraHonkZKProof,
    c3pi0: [Field; 3],
    ikh0: pub Field,
    ivk1: UltraHonkVerificationKey,
    iprf1: UltraHonkZKProof,
    c3pi1: [Field; 3],
    ikh1: pub Field,
    avk: UltraHonkVerificationKey,
    aproof: UltraHonkProof,
    api: [Field; C3_FOLD_PUBLIC_LEN],
    akh: pub Field,
    gen_hash0: pub Field,
    gen_hash1: pub Field
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    // acc = KERNEL GENESIS proof, verified non-ZK; the batch leaves then claim
    // fresh accumulator slots (compact layout).
    verify_honk_proof_non_zk(avk, aproof, api, akh);
    let (p0, m0, c0) = leaf3::<1>(ivk0, iprf0, c3pi0, ikh0, api);
    let (p1, m1, c1) = leaf3::<2>(ivk1, iprf1, c3pi1, ikh1, api);
    let mut pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut ct: [Field; C3_SLOTS] = [0; C3_SLOTS];
    // carry the kernel anchor (slot 0) from the genesis accumulator
    pk[0] = api[4]; msg[0] = api[4 + C3_SLOTS]; ct[0] = api[4 + (2 * C3_SLOTS)];
    pk[1] = p0; msg[1] = m0; ct[1] = c0;
    pk[2] = p1; msg[2] = m1; ct[2] = c1;
    (pk, msg, ct)
}
