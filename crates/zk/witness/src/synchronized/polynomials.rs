// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::invalid;
use crate::{validation, WitnessError};
use e3_zk_config::synchronized::Configs;
use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis, RepresentationTag};

fn check<R: RepresentationTag>(config: &Configs, poly: &Poly<R>) -> Result<(), WitnessError> {
    let matrix = poly.coefficients();
    validation::context(
        "synchronized decryption polynomial",
        poly.ctx(),
        matrix.nrows(),
        matrix.ncols(),
        &config.threshold,
    )?;
    if matrix
        .outer_iter()
        .zip(config.threshold.moduli())
        .any(|(row, q)| row.iter().any(|v| v >= q))
    {
        return Err(invalid("noncanonical synchronized decryption coefficient"));
    }
    Ok(())
}

pub(super) fn native_rows(
    config: &Configs,
    poly: &Poly<PowerBasis>,
) -> Result<Vec<Vec<u64>>, WitnessError> {
    check(config, poly)?;
    Ok(poly
        .coefficients()
        .outer_iter()
        .map(|row| row.to_vec())
        .collect())
}

pub(super) fn components(
    config: &Configs,
    ciphertext: &Ciphertext,
) -> Result<[Poly<PowerBasis>; 2], WitnessError> {
    if ciphertext.level != 0 || ciphertext.len() != 2 {
        return Err(invalid(
            "synchronized decryption requires two level-zero components",
        ));
    }
    for component in ciphertext.iter() {
        check(config, component)?;
    }
    Ok([
        ciphertext[0].clone().into_power_basis(),
        ciphertext[1].clone().into_power_basis(),
    ])
}
