// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Federated-averaging validity leg (ParamSet 5): proves the TWO message
//! polynomials `m_grad` / `m_count` (the SAME `m`s the two Greco ct0 legs
//! commit to) are `gradient_block(g)` (entries `|g_j| <= 1` on
//! coefficients `1..=D`, the `1.0` marker on `D + 1`, zero elsewhere) and
//! `constant(count)` (`1 <= count < 1024` on coefficient 0, zero
//! elsewhere), and that `sum_j G_j^2 <= norm_bound`.
//!
//! Public inputs: `norm_bound` (the round's poisoning bound, `x 2^32`),
//! `address` (the on-chain gate equates it to `msg.sender`), `index` (the
//! client's position in the round's registered list). Public outputs:
//! `(m_commitment_grad, m_commitment_count)`.
//! On-chain word order:
//! `[norm_bound, address, index, m_commitment_grad, m_commitment_count]`.

use lib::configs::ckks_fedavg_ps5::{
    CKKS_FEDAVG_BIT_M, CKKS_FEDAVG_CONFIGS, CKKS_FEDAVG_D, CKKS_FEDAVG_N,
};
use lib::core::threshold::ckks_fedavg_validity::fedavg_validity;
use lib::math::polynomial::Polynomial;

fn main(
    m_grad: Polynomial<CKKS_FEDAVG_N>,
    m_count: Polynomial<CKKS_FEDAVG_N>,
    g: [Field; CKKS_FEDAVG_D],
    count: Field,
    norm_bound: pub Field,
    address: pub Field,
    index: pub u32,
) -> pub (Field, Field) {
    fedavg_validity::<CKKS_FEDAVG_N, CKKS_FEDAVG_BIT_M, CKKS_FEDAVG_D>(
        CKKS_FEDAVG_CONFIGS,
        m_grad,
        m_count,
        g,
        count,
        norm_bound,
        address,
        index,
    )
}
