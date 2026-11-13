// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_dkg_pk_commitment;
use crate::math::polynomial::Polynomial;

/// DKG public key commitment (C0).
///
/// **Role:** Bind the ciphernode DKG public key used to encrypt outgoing shares in DKG, and pin
/// every coefficient to its centred residue `[-(q_i - 1) / 2, (q_i - 1) / 2]`.
///
/// The bound is checked here, once per key, so that each C3 encrypting to this key can open the
/// commitment with checked packing instead of range-checking the key again (the bound transfers
/// through the injective opening). It also puts a malformed key's failure on its owner: an
/// unbounded key is rejected by its own C0 rather than by every dealer's C3.
///
/// **Produces:**
/// - `commit(pk_dkg)` -> C3 (share encryption).
pub struct Pk<let N: u32, let L: u32, let BIT_PK: u32> {
    /// DKG public key first component for each CRT modulus.
    /// pk0[i] is a degree N-1 polynomial for modulus q_i.
    pk0: [Polynomial<N>; L],
    /// DKG public key second component for each CRT modulus.
    /// pk1[i] is a degree N-1 polynomial for modulus q_i.
    pk1: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32> Pk<N, L, BIT_PK> {
    /// Creates a new DKG public key commitment circuit instance.
    ///
    /// # Arguments
    ///
    /// * `pk0` - First component of DKG public key (one polynomial per CRT modulus)
    /// * `pk1` - Second component of DKG public key (one polynomial per CRT modulus)
    pub fn new(pk0: [Polynomial<N>; L], pk1: [Polynomial<N>; L]) -> Self {
        Pk { pk0, pk1 }
    }

    /// Range-checks the key to its centred window modulo `qis`, then returns the binding
    /// commitment. Every centred bound fits `BIT_PK` bits, so the plain packing is injective.
    pub fn execute(self, qis: [Field; L]) -> Field {
        for i in 0..L {
            let bound = (qis[i] - 1) / 2;
            self.pk0[i].range_check_2bounds::<BIT_PK>(bound, bound);
            self.pk1[i].range_check_2bounds::<BIT_PK>(bound, bound);
        }
        compute_dkg_pk_commitment::<N, L, BIT_PK>(self.pk0, self.pk1)
    }
}

#[test]
fn test_c0_accepts_a_centred_key() {
    // q = 101: the centred window is [-50, 50].
    let pk0 = [Polynomial::new([50, -50, 0, 7])];
    let pk1 = [Polynomial::new([-1, 1, 49, -49])];
    let circuit: Pk<4, 1, 7> = Pk::new(pk0, pk1);
    assert(circuit.execute([101]) == compute_dkg_pk_commitment::<4, 1, 7>(pk0, pk1));
}

#[test(should_fail)]
fn test_c0_rejects_a_coefficient_outside_the_centred_window() {
    let circuit: Pk<4, 1, 7> = Pk::new(
        [Polynomial::new([51, 0, 0, 0])],
        [Polynomial::new([0, 0, 0, 0])],
    );
    let _ = circuit.execute([101]);
}

#[test(should_fail)]
fn test_c0_rejects_a_non_canonical_second_component() {
    // -51 is congruent to 50 mod 101 but outside the centred window.
    let circuit: Pk<4, 1, 7> = Pk::new(
        [Polynomial::new([0, 0, 0, 0])],
        [Polynomial::new([0, -51, 0, 0])],
    );
    let _ = circuit.execute([101]);
}
