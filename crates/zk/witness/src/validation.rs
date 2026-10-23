// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Concrete polynomial shapes required by the compiled BFV circuits.

use crate::WitnessError;
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::BfvParameters;
use fhe_math::rq::Context;

pub(crate) fn parameters(
    name: &str,
    actual: &BfvParameters,
    expected: &BfvParameters,
) -> Result<(), WitnessError> {
    if actual.degree() != expected.degree()
        || actual.plaintext() != expected.plaintext()
        || actual.moduli() != expected.moduli()
        || actual.variance() != expected.variance()
        || actual.get_error1_variance() != expected.get_error1_variance()
    {
        return Err(WitnessError::Other(format!(
            "{name} parameters do not match the supplied circuit configuration"
        )));
    }
    Ok(())
}

pub(crate) fn polynomial(
    name: &str,
    value: &Polynomial,
    degree: usize,
) -> Result<(), WitnessError> {
    if value.coefficients().len() != degree {
        return Err(WitnessError::Other(format!(
            "{name} has {} coefficients; expected {degree}",
            value.coefficients().len(),
        )));
    }
    Ok(())
}

pub(crate) fn crt(
    name: &str,
    value: &CrtPolynomial,
    params: &BfvParameters,
) -> Result<(), WitnessError> {
    if value.limbs.len() != params.moduli().len() {
        return Err(WitnessError::Other(format!(
            "{name} has {} CRT limbs; expected {}",
            value.limbs.len(),
            params.moduli().len(),
        )));
    }
    for (index, limb) in value.limbs.iter().enumerate() {
        polynomial(&format!("{name}[{index}]"), limb, params.degree())?;
    }
    Ok(())
}

pub(crate) fn context(
    name: &str,
    actual: &Context,
    rows: usize,
    columns: usize,
    params: &BfvParameters,
) -> Result<(), WitnessError> {
    let expected = params.context_at_level(0)?;
    if actual != expected.as_ref() || rows != params.moduli().len() || columns != params.degree() {
        return Err(WitnessError::Other(format!(
            "{name} does not match the configured level-zero BFV context and shape",
        )));
    }
    Ok(())
}
