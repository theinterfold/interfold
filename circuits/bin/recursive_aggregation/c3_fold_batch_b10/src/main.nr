// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a r51 (box-2): B=10-leaf production-fit c3 fold gate (execution-card step 3).
//! Public ABI == `c3_fold` return: 3 x C3_SLOTS pub fields + acc_key_hash /
//! is_first_step / slot0 / slot1 pub (rest private). Same 4-prefix ABI
//! as c3_fold_batch_b3; shared `c3_fold_batch_lib::c3_batch` gate untouched.

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
    vk2: UltraHonkVerificationKey,
    proof2: UltraHonkZKProof,
    c3c: [Field; 3],
    kh2: Field,
    vk3: UltraHonkVerificationKey,
    proof3: UltraHonkZKProof,
    c3d: [Field; 3],
    kh3: Field,
    vk4: UltraHonkVerificationKey,
    proof4: UltraHonkZKProof,
    c3e: [Field; 3],
    kh4: Field,
    vk5: UltraHonkVerificationKey,
    proof5: UltraHonkZKProof,
    c3f: [Field; 3],
    kh5: Field,
    vk6: UltraHonkVerificationKey,
    proof6: UltraHonkZKProof,
    c3g: [Field; 3],
    kh6: Field,
    vk7: UltraHonkVerificationKey,
    proof7: UltraHonkZKProof,
    c3h: [Field; 3],
    kh7: Field,
    vk8: UltraHonkVerificationKey,
    proof8: UltraHonkZKProof,
    c3i: [Field; 3],
    kh8: Field,
    vk9: UltraHonkVerificationKey,
    proof9: UltraHonkZKProof,
    c3j: [Field; 3],
    kh9: Field,
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot0: pub u32,
    slot1: pub u32,
    slot2: u32,
    slot3: u32,
    slot4: u32,
    slot5: u32,
    slot6: u32,
    slot7: u32,
    slot8: u32,
    slot9: u32,
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    let inners: [C3Inner; 10] = [
        C3Inner { vk: vk0, proof: proof0, c3_public_inputs: c3a, key_hash: kh0 },
        C3Inner { vk: vk1, proof: proof1, c3_public_inputs: c3b, key_hash: kh1 },
        C3Inner { vk: vk2, proof: proof2, c3_public_inputs: c3c, key_hash: kh2 },
        C3Inner { vk: vk3, proof: proof3, c3_public_inputs: c3d, key_hash: kh3 },
        C3Inner { vk: vk4, proof: proof4, c3_public_inputs: c3e, key_hash: kh4 },
        C3Inner { vk: vk5, proof: proof5, c3_public_inputs: c3f, key_hash: kh5 },
        C3Inner { vk: vk6, proof: proof6, c3_public_inputs: c3g, key_hash: kh6 },
        C3Inner { vk: vk7, proof: proof7, c3_public_inputs: c3h, key_hash: kh7 },
        C3Inner { vk: vk8, proof: proof8, c3_public_inputs: c3i, key_hash: kh8 },
        C3Inner { vk: vk9, proof: proof9, c3_public_inputs: c3j, key_hash: kh9 },
    ];
    let slots: [u32; 10] = [
        slot0, slot1, slot2, slot3, slot4, slot5, slot6, slot7, slot8, slot9,
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
