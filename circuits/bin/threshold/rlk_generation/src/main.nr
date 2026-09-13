// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::N_PARTIES;
use lib::configs::default::threshold::{
    GADGET_DIM, L, N, RLK_GENERATION_BIT_D, RLK_GENERATION_CONFIGS,
};
use lib::core::threshold::lbfv_proof_domain::{LbfvProofSession, validate_generation_statement};
use lib::math::commitments::{
    compute_rlk_d0_commitment, compute_rlk_d2_commitment, compute_rlk_limb_d0_commitment,
    compute_rlk_limb_d2_commitment,
};
use lib::math::polynomial::Polynomial;

pub global RLK_LIMB_PUBLIC_LEN: u32 = 11;

/// Verify all CRT-limb proofs for one RLK row and restore the legacy row commitments.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    party_id: pub u32,
    row_index: pub u32,
    limb_vk: UltraHonkVerificationKey,
    limb_proofs: [UltraHonkZKProof; L],
    limb_public_inputs: [[Field; RLK_LIMB_PUBLIC_LEN]; L],
    limb_key_hash: Field,
    d0: [Polynomial<N>; L],
    d2: [Polynomial<N>; L],
) -> pub (Field, Field, Field, Field, Field) {
    validate_generation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        party_id,
        row_index,
    );

    for limb_index in 0..L {
        d0[limb_index].range_check_2bounds::<RLK_GENERATION_BIT_D>(
            RLK_GENERATION_CONFIGS.r2_d0_bounds[limb_index],
            RLK_GENERATION_CONFIGS.r2_d0_bounds[limb_index],
        );
        d2[limb_index].range_check_2bounds::<RLK_GENERATION_BIT_D>(
            RLK_GENERATION_CONFIGS.r2_d2_bounds[limb_index],
            RLK_GENERATION_CONFIGS.r2_d2_bounds[limb_index],
        );
        verify_honk_proof(
            limb_vk,
            limb_proofs[limb_index],
            limb_public_inputs[limb_index],
            limb_key_hash,
        );

        assert(limb_public_inputs[limb_index][0] == session_id_hi);
        assert(limb_public_inputs[limb_index][1] == session_id_lo);
        assert(limb_public_inputs[limb_index][2] == party_id as Field);
        assert(limb_public_inputs[limb_index][3] == row_index as Field);
        assert(limb_public_inputs[limb_index][4] == limb_index as Field);
        assert(limb_public_inputs[limb_index][5] == limb_public_inputs[0][5]);
        assert(limb_public_inputs[limb_index][6] == limb_public_inputs[0][6]);
        assert(limb_public_inputs[limb_index][7] == limb_public_inputs[0][7]);
        assert(limb_public_inputs[limb_index][8] == limb_public_inputs[0][8]);
        assert(
            compute_rlk_limb_d0_commitment::<N, RLK_GENERATION_BIT_D>(
                row_index,
                limb_index,
                d0[limb_index],
            )
                == limb_public_inputs[limb_index][9],
        );
        assert(
            compute_rlk_limb_d2_commitment::<N, RLK_GENERATION_BIT_D>(
                row_index,
                limb_index,
                d2[limb_index],
            )
                == limb_public_inputs[limb_index][10],
        );
    }

    let d0_commitment = compute_rlk_d0_commitment::<N, L, RLK_GENERATION_BIT_D>(d0);
    let d2_commitment = compute_rlk_d2_commitment::<N, L, RLK_GENERATION_BIT_D>(d2);

    (
        limb_public_inputs[0][5], limb_public_inputs[0][6], d0_commitment, d2_commitment,
        limb_key_hash,
    )
}
