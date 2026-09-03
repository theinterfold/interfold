// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Salary-survey app leg (ParamSet 3): proves the message polynomial `m`
//! (the SAME `m` the Greco ct0 leg commits to) is the slot-replicated
//! encoding of `value_raw / cap` with `0 <= value_raw <= cap`.
//!
//! Public inputs: `cap`. Public output: `m_commitment` (must equal the
//! ct0 leg's third output on-chain).

use lib::configs::ckks_app_ps3::{
    CKKS_SALARY_BIT_M, CKKS_SALARY_BIT_TAIL, CKKS_SALARY_CONFIGS, CKKS_SALARY_N,
};
use lib::core::threshold::ckks_app_validity::salary_validity;
use lib::math::polynomial::Polynomial;

fn main(m: Polynomial<CKKS_SALARY_N>, value_raw: Field, cap: pub Field) -> pub Field {
    salary_validity::<CKKS_SALARY_N, CKKS_SALARY_BIT_M, CKKS_SALARY_BIT_TAIL>(
        CKKS_SALARY_CONFIGS,
        m,
        value_raw,
        cap,
    )
}
