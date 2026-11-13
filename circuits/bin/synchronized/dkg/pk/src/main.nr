// SPDX-License-Identifier: LGPL-3.0-only

use lib::configs::synchronized::sync_insecure_64::{L, N, PK_BIT_PK, QIS};
use lib::core::dkg::pk::Pk;
use lib::math::polynomial::Polynomial;

fn main(pk0is: [Polynomial<N>; L], pk1is: [Polynomial<N>; L]) -> pub Field {
    let pk: Pk<N, L, PK_BIT_PK> = Pk::new(pk0is, pk1is);
    pk.execute(QIS)
}
