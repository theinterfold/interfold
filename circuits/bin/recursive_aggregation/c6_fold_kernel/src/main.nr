// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Same IO as [`c6_fold`](../c6_fold/src/main.nr) but **only** verifies the inner
//! `ThresholdShareDecryption` proof. Used to mint a fixed genesis `UltraHonkProof` that bootstraps
//! the real `c6_fold` circuit, which always runs `verify_honk_proof_non_zk` on the accumulator (see
//! `c6_fold`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};
use lib::configs::default::{DECRYPTOR_COUNT, N_PARTIES, T};

/// Same C6 public row as `c6_fold`.
pub global C6_PUBLIC_LEN: u32 = 7 + DECRYPTOR_COUNT + (2 * N_PARTIES);

/// Same shape as `c6_fold`: 4 pub parameters + the common domain limbs +
/// 4 columns of `T + 1` party slots each.
pub global C6_KEY_SLOTS: u32 = (T + 1) * N_PARTIES;
pub global C6_FOLD_PUBLIC_LEN: u32 =
    6 + (4 * (T + 1)) + (2 * C6_KEY_SLOTS) + DECRYPTOR_COUNT;

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proof: UltraHonkZKProof,
    c6_public_inputs: [Field; C6_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C6_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot_index: pub u32,
) -> pub (Field, Field, [Field; T + 1], [Field; T + 1], [Field; T + 1], [Field; T + 1], [Field; C6_KEY_SLOTS], [Field; C6_KEY_SLOTS], [Field; DECRYPTOR_COUNT]) {
    assert(slot_index < T + 1);

    verify_honk_proof(inner_vk, inner_proof, c6_public_inputs, inner_key_hash);

    // Signature parity with `c6_fold`: see `c3_fold_kernel`.
    let _ = (acc_vk, acc_proof, acc_key_hash, acc_public_inputs);

    assert(is_first_step);

    let sk_new = c6_public_inputs[0];
    let ct_new = c6_public_inputs[1];
    let c0_new = c6_public_inputs[2];
    let domain_hi = c6_public_inputs[3];
    let domain_lo = c6_public_inputs[4];
    let d_new = c6_public_inputs[C6_PUBLIC_LEN - 1];
    let outgoing_start = 6 + DECRYPTOR_COUNT;
    let incoming_start = outgoing_start + N_PARTIES;

    let mut out_sk: [Field; T + 1] = [0; T + 1];
    let mut out_esm: [Field; T + 1] = [0; T + 1];
    let mut out_ct: [Field; T + 1] = [0; T + 1];
    let mut out_d: [Field; T + 1] = [0; T + 1];
    let mut out_outgoing: [Field; C6_KEY_SLOTS] = [0; C6_KEY_SLOTS];
    let mut out_incoming: [Field; C6_KEY_SLOTS] = [0; C6_KEY_SLOTS];

    for i in 0..(T + 1) {
        let idx = i as u32;
        if idx == slot_index {
            out_sk[i] = sk_new;
            out_esm[i] = c0_new;
            out_ct[i] = ct_new;
            out_d[i] = d_new;
            for k in 0..N_PARTIES {
                out_outgoing[i * N_PARTIES + k] = c6_public_inputs[outgoing_start + k];
                out_incoming[i * N_PARTIES + k] = c6_public_inputs[incoming_start + k];
            }
        }
    }

    let mut out_decryptors: [Field; DECRYPTOR_COUNT] = [0; DECRYPTOR_COUNT];
    for d in 0..DECRYPTOR_COUNT {
        out_decryptors[d] = c6_public_inputs[6 + d];
    }
    assert(c6_public_inputs[5] + 1 == out_decryptors[slot_index]);

    (
        domain_hi, domain_lo, out_sk, out_esm, out_ct, out_d, out_outgoing, out_incoming,
        out_decryptors,
    )
}
