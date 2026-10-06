// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C6 fold: one inner ZK `ThresholdShareDecryption` proof per step, chained with the
//! previous accumulator (`c6_fold` non-ZK proof, or a fixed genesis proof from `c6_fold_kernel` on
//! the first step; see `crates/zk-prover` and `c6_fold_kernel`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::{DECRYPTOR_COUNT, N_PARTIES, T};

/// C6 public row: `sk`, `ct`, `c0`, two domain limbs, `party_idx`, the
/// decryptor ids, two key-commitment rows, then `d_commitment`.
pub global C6_PUBLIC_LEN: u32 = 7 + DECRYPTOR_COUNT + (2 * N_PARTIES);

pub global C6_KEY_SLOTS: u32 = (T + 1) * N_PARTIES;

/// Four columns of `T + 1` slots, then the outgoing and incoming PRF-key
/// commitments opened by each C6 leaf.
pub global C6_FOLD_PUBLIC_LEN: u32 =
    6 + (4 * (T + 1)) + (2 * C6_KEY_SLOTS) + DECRYPTOR_COUNT;

pub global C6_FOLD_PREFIX_LEN: u32 = 6;

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

    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let sk_new = c6_public_inputs[0];
    let ct_new = c6_public_inputs[1];
    let c0_new = c6_public_inputs[2];
    let domain_hi = c6_public_inputs[3];
    let domain_lo = c6_public_inputs[4];
    let d_new = c6_public_inputs[C6_PUBLIC_LEN - 1];
    let outgoing_start = 6 + DECRYPTOR_COUNT;
    let incoming_start = outgoing_start + N_PARTIES;
    let decryptor_start = 6;

    if !is_first_step {
        assert(acc_public_inputs[4] == domain_hi);
        assert(acc_public_inputs[5] == domain_lo);
    }

    let mut out_sk: [Field; T + 1] = [0; T + 1];
    let mut out_esm: [Field; T + 1] = [0; T + 1];
    let mut out_ct: [Field; T + 1] = [0; T + 1];
    let mut out_d: [Field; T + 1] = [0; T + 1];
    let mut out_outgoing: [Field; C6_KEY_SLOTS] = [0; C6_KEY_SLOTS];
    let mut out_incoming: [Field; C6_KEY_SLOTS] = [0; C6_KEY_SLOTS];

    for i in 0..(T + 1) {
        let idx = i as u32;
        if is_first_step {
            if idx == slot_index {
                out_sk[i] = sk_new;
                out_esm[i] = c0_new;
                out_ct[i] = ct_new;
                out_d[i] = d_new;
                for k in 0..N_PARTIES {
                    out_outgoing[i * N_PARTIES + k] = c6_public_inputs[outgoing_start + k];
                    out_incoming[i * N_PARTIES + k] = c6_public_inputs[incoming_start + k];
                }
            } else {
                out_sk[i] = 0;
                out_esm[i] = 0;
                out_ct[i] = 0;
                out_d[i] = 0;
            }
        } else {
            let prior_sk = acc_public_inputs[C6_FOLD_PREFIX_LEN + i];
            let prior_esm = acc_public_inputs[C6_FOLD_PREFIX_LEN + (T + 1) + i];
            let prior_ct = acc_public_inputs[C6_FOLD_PREFIX_LEN + (2 * (T + 1)) + i];
            let prior_d = acc_public_inputs[C6_FOLD_PREFIX_LEN + (3 * (T + 1)) + i];

            if idx == slot_index {
                assert(prior_sk == 0);
                assert(prior_esm == 0);
                assert(prior_ct == 0);
                assert(prior_d == 0);
                out_sk[i] = sk_new;
                out_esm[i] = c0_new;
                out_ct[i] = ct_new;
                out_d[i] = d_new;
                for k in 0..N_PARTIES {
                    out_outgoing[i * N_PARTIES + k] = c6_public_inputs[outgoing_start + k];
                    out_incoming[i * N_PARTIES + k] = c6_public_inputs[incoming_start + k];
                }
            } else {
                out_sk[i] = prior_sk;
                out_esm[i] = prior_esm;
                out_ct[i] = prior_ct;
                out_d[i] = prior_d;
                let prior_keys = C6_FOLD_PREFIX_LEN + (4 * (T + 1)) + (i * N_PARTIES);
                for k in 0..N_PARTIES {
                    out_outgoing[i * N_PARTIES + k] = acc_public_inputs[prior_keys + k];
                    out_incoming[i * N_PARTIES + k] = acc_public_inputs[prior_keys
                        + C6_KEY_SLOTS
                        + k];
                }
            }
        }
    }

    let mut out_decryptors: [Field; DECRYPTOR_COUNT] = [0; DECRYPTOR_COUNT];
    let stored_decryptors = C6_FOLD_PREFIX_LEN + (4 * (T + 1)) + (2 * C6_KEY_SLOTS);
    for d in 0..DECRYPTOR_COUNT {
        let leaf_id = c6_public_inputs[decryptor_start + d];
        if is_first_step {
            out_decryptors[d] = leaf_id;
        } else {
            assert(leaf_id == acc_public_inputs[stored_decryptors + d]);
            out_decryptors[d] = leaf_id;
        }
    }
    assert(c6_public_inputs[5] + 1 == out_decryptors[slot_index]);

    (
        domain_hi, domain_lo, out_sk, out_esm, out_ct, out_d, out_outgoing, out_incoming,
        out_decryptors,
    )
}
