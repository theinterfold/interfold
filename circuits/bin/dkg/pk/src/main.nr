// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{L, N, QIS};
use lib::configs::default::dkg::PK_BIT_PK;
use lib::core::dkg::pk::Pk;
use lib::math::polynomial::Polynomial;

fn main(pk0is: [Polynomial<N>; L], pk1is: [Polynomial<N>; L]) -> pub Field {
    let pk: Pk<N, L, PK_BIT_PK> = Pk::new(pk0is, pk1is);
    pk.execute(QIS)
}
