// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5 r9 PoC bin: B=2-leaf production-fit c3 fold gate.
//! Public ABI == `c3_fold` return: 3 x C3_SLOTS pub fields + acc_key_hash /
//! is_first_step / slots pub params (key-hash chain preserved).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use c3_fold_batch_lib::{c3_batch, C3Inner};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_FOLD_PUBLIC_LEN: u32 = 4 + (3 * C3_SLOTS);

fn main(
    vk0: UltraHonkVerificationKey,
    proof0: UltraHonkZKProof,
    c3a: [Field; 3],
    kh0: Field,
    vk1: UltraHonkVerificationKey,
    proof1: UltraHonkZKProof,
    c3b: [Field; 3],
    kh1: Field,
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot0: pub u32,
    slot1: pub u32,
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    let inners: [C3Inner; 2] = [
        C3Inner { vk: vk0, proof: proof0, c3_public_inputs: c3a, key_hash: kh0 },
        C3Inner { vk: vk1, proof: proof1, c3_public_inputs: c3b, key_hash: kh1 },
    ];
    let slots: [u32; 2] = [
        slot0, slot1,
    ];
    c3_batch(
        inners,
        acc_vk,
        acc_proof,
        acc_public_inputs,
        acc_key_hash,
        is_first_step,
        slots,
    )
}
