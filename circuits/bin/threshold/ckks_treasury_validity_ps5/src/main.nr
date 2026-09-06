// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Treasury-risk validity leg (ParamSet 5): proves the THREE message
//! polynomials `m_fwd` / `m_rev` / `m_mask` (the SAME `m`s the three Greco
//! ct0 legs commit to) are `forward(x)`, `reversed(w o x)` and `mask(m)`
//! in the ParamSet-5 coefficient layout, with `x_a in [0, 1]`, the PUBLIC
//! round weights `w` (`|w_a| <= 1`) and `m_j in [0, 1024)`.
//!
//! Public inputs: `weights[4]` (the round's registered weights, `x 2^16`,
//! negatives as `p - |W|`), `address` (the on-chain gate equates it to
//! `msg.sender`), `index` (the DAO's position in the round's registered
//! list). Public outputs:
//! `(m_commitment_fwd, m_commitment_rev, m_commitment_mask)`.
//! On-chain word order:
//! `[w_0..w_3, address, index, m_commitment_fwd, m_commitment_rev, m_commitment_mask]`.

use lib::configs::ckks_treasury_ps5::{CKKS_TREASURY_BIT_M, CKKS_TREASURY_CONFIGS, CKKS_TREASURY_N};
use lib::core::threshold::ckks_treasury_validity::{ASSETS, MASK_WIDTH, treasury_validity};
use lib::math::polynomial::Polynomial;

fn main(
    m_fwd: Polynomial<CKKS_TREASURY_N>,
    m_rev: Polynomial<CKKS_TREASURY_N>,
    m_mask: Polynomial<CKKS_TREASURY_N>,
    x: [Field; ASSETS],
    mask: [Field; MASK_WIDTH],
    weights: pub [Field; ASSETS],
    address: pub Field,
    index: pub u32,
) -> pub (Field, Field, Field) {
    treasury_validity::<CKKS_TREASURY_N, CKKS_TREASURY_BIT_M>(
        CKKS_TREASURY_CONFIGS,
        m_fwd,
        m_rev,
        m_mask,
        x,
        mask,
        weights,
        address,
        index,
    )
}
