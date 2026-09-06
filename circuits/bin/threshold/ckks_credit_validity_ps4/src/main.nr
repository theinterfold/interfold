// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Credit-scoring v2 validity leg (ParamSet 4): proves the TWO message
//! polynomials `m_z` / `m_m` (the SAME `m`s the two Greco ct0 legs
//! commit to) are the slot-`index` encodings of the public model's
//! logit over the applicant's Merkle-attested features and of the
//! applicant's output mask, every other slot 0, and that
//! `poseidon([address, x_0, .., x_7])` is a leaf under `merkle_root`.
//!
//! Public inputs: `cap`, `address` (the on-chain gate equates it to
//! `msg.sender`), `merkle_root` (the round's issuer root), `index` (the
//! applicant's position in the round's registered list), `weights[8]`
//! and `bias` (the round's registered model, `x 2^16`, negatives as
//! `p - |w|`). Public outputs: `(m_commitment_z, m_commitment_m)`.
//! On-chain word order:
//! `[cap, address, merkle_root, index, w_0..w_7, bias, m_commitment_z, m_commitment_m]`.

use lib::configs::ckks_credit_ps4::{
    CKKS_CREDIT_BIT_M, CKKS_CREDIT_CONFIGS, CKKS_CREDIT_MERKLE_MAX_DEPTH, CKKS_CREDIT_N,
};
use lib::core::threshold::ckks_credit_validity::{credit_validity, FEATURES};
use lib::math::polynomial::Polynomial;

fn main(
    m_z: Polynomial<CKKS_CREDIT_N>,
    m_m: Polynomial<CKKS_CREDIT_N>,
    features: [Field; FEATURES],
    depth: u32,
    indices: [bool; CKKS_CREDIT_MERKLE_MAX_DEPTH],
    siblings: [Field; CKKS_CREDIT_MERKLE_MAX_DEPTH],
    mask: Field,
    cap: pub Field,
    address: pub Field,
    merkle_root: pub Field,
    index: pub u32,
    weights: pub [Field; FEATURES],
    bias: pub Field,
) -> pub (Field, Field) {
    credit_validity::<CKKS_CREDIT_N, CKKS_CREDIT_BIT_M, CKKS_CREDIT_MERKLE_MAX_DEPTH>(
        CKKS_CREDIT_CONFIGS,
        m_z,
        m_m,
        features,
        depth,
        indices,
        siblings,
        mask,
        cap,
        address,
        merkle_root,
        index,
        weights,
        bias,
    )
}
