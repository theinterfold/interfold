// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Helpers for converting fhe-math `Poly<R>` values.

use fhe_math::rq::{Ntt, NttShoup, Poly, PowerBasis};

/// Borrowed conversion of any RNS polynomial to power-basis form.
pub trait ToPowerBasisPoly {
    /// Returns a power-basis copy suitable for coefficient extraction.
    fn to_power_basis_poly(&self) -> Poly<PowerBasis>;
}

impl ToPowerBasisPoly for Poly<PowerBasis> {
    fn to_power_basis_poly(&self) -> Poly<PowerBasis> {
        self.clone()
    }
}

impl ToPowerBasisPoly for Poly<Ntt> {
    fn to_power_basis_poly(&self) -> Poly<PowerBasis> {
        self.to_power_basis()
    }
}

impl ToPowerBasisPoly for Poly<NttShoup> {
    fn to_power_basis_poly(&self) -> Poly<PowerBasis> {
        self.to_power_basis()
    }
}

impl<T: ToPowerBasisPoly + ?Sized> ToPowerBasisPoly for &T {
    fn to_power_basis_poly(&self) -> Poly<PowerBasis> {
        (*self).to_power_basis_poly()
    }
}
