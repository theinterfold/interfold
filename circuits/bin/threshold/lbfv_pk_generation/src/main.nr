// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::N_PARTIES;
use lib::configs::default::threshold::{GADGET_DIM, L, N, PK_GENERATION_BIT_PK};
use lib::core::threshold::lbfv_proof_domain::{LbfvProofSession, validate_generation_statement};
use lib::math::commitments::{compute_lbfv_pk_limb_commitment, compute_threshold_pk_commitment};
use lib::math::polynomial::Polynomial;

pub global LBFV_PK_LIMB_PUBLIC_LEN: u32 = 8;

/// Verify all CRT-limb proofs for one l-BFV public-key row.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    party_id: pub u32,
    row_index: pub u32,
    limb_vk: UltraHonkVerificationKey,
    limb_proofs: [UltraHonkZKProof; L],
    limb_public_inputs: [[Field; LBFV_PK_LIMB_PUBLIC_LEN]; L],
    limb_key_hash: Field,
    pk0: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    validate_generation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        party_id,
        row_index,
    );

    for limb_index in 0..L {
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
        assert(
            compute_lbfv_pk_limb_commitment::<N, PK_GENERATION_BIT_PK>(
                row_index,
                limb_index,
                pk0[limb_index],
            )
                == limb_public_inputs[limb_index][7],
        );
    }

    let pk_commitment = compute_threshold_pk_commitment::<N, L, PK_GENERATION_BIT_PK>(pk0);
    (limb_public_inputs[0][5], pk_commitment, limb_key_hash)
}
