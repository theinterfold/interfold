// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Private-matching validity leg (ParamSet 5): proves the TWO message
//! polynomials `m_vec` / `m_mask` (the SAME `m`s the two Greco ct0 legs
//! commit to) are, respectively, the `forward` (role 0 = A) or `reversed`
//! (role 1 = B) coefficient encoding of a length-16 vector with
//! `|v_j| <= 1` (fixed point `V / 2^16`), and the `mask` layout of 128
//! integers in `[0, 1024)`, every other coefficient 0.
//!
//! Public inputs: `role` (0 = A, 1 = B; the on-chain gate equates it to
//! the sender's registered slot), `address` (equated to `msg.sender`) and
//! `index` (the registered slot). Public outputs:
//! `(m_commitment_vec, m_commitment_mask)`. On-chain word order:
//! `[role, address, index, m_commitment_vec, m_commitment_mask]`.

use lib::configs::ckks_matching_ps5::{CKKS_MATCHING_BIT_M, CKKS_MATCHING_CONFIGS, CKKS_MATCHING_N};
use lib::core::threshold::ckks_matching_validity::{K, MASK_WIDTH, matching_validity};
use lib::math::polynomial::Polynomial;

fn main(
    m_vec: Polynomial<CKKS_MATCHING_N>,
    m_mask: Polynomial<CKKS_MATCHING_N>,
    values: [Field; K],
    mask: [Field; MASK_WIDTH],
    role: pub u32,
    address: pub Field,
    index: pub u32,
) -> pub (Field, Field) {
    matching_validity::<CKKS_MATCHING_N, CKKS_MATCHING_BIT_M>(
        CKKS_MATCHING_CONFIGS,
        m_vec,
        m_mask,
        values,
        mask,
        role,
        address,
        index,
    )
}
