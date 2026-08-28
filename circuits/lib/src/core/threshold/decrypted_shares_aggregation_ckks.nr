// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS decrypted shares aggregation (C7-CKKS).
//!
//! CKKS variant of `decrypted_shares_aggregation`. The share-combination
//! steps are identical (Lagrange interpolation per CRT basis + CRT glue);
//! the BFV decode step (`-Q^{-1} * t * u mod t`) is REMOVED because the CKKS
//! plaintext is the recovered ring element itself (`delta*m + e`): dividing
//! by the scale `delta` is a real-number operation performed off-circuit.
//! Instead, the circuit binds the recovered polynomial `u_global` as a
//! public witness, so the on-chain consumer gets the exact fixed-point
//! coefficients the committee reconstructed.
//!
//! The upstream C6 (`share_decryption`) circuit is scheme-agnostic — the
//! relation `d = c0 + c1*sk + e_sm + r2*cyclo + r1*q` has no plaintext
//! modulus — and is reused for CKKS without modification.

use crate::core::threshold::decrypted_shares_aggregation::{
    compute_all_lagrange_coeffs, compute_crt_components, verify_crt_reconstruction,
};
use crate::math::commitments::compute_threshold_decryption_share_commitment;
use crate::math::polynomial::Polynomial;

/// Parameters for CKKS decrypted shares aggregation.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// CKKS decrypted shares aggregation (C7-CKKS).
///
/// **Role:** Combine partial CKKS decryption shares into the plaintext ring
/// element (Lagrange + CRT). No modular decode: the scaled fixed-point
/// coefficients ARE the result.
///
/// **Consumes:** C6 `d` commitments for each reconstructing party (same
/// order as shares).
///
/// **Verifies:** Share binding to C6; Lagrange combine per limb; CRT glue;
/// claimed plaintext equals the reconstruction.
pub struct DecryptedSharesAggregationCkks<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let BIT_D_NATIVE: u32> {
    /// Circuit parameters.
    configs: Configs<L>,

    /// Public `d` commitments from C6 (one per reconstructing party).
    expected_d_commitments: [Field; T + 1],

    /// Decryption shares from t+1 parties (secret witnesses).
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],

    /// Party IDs (x-coordinates), strictly increasing (public witnesses).
    party_ids: [Field; T + 1],

    /// The recovered plaintext ring element `u_global = delta*m + e` mod Q
    /// (public witness). Off-circuit, the app centers each coefficient mod Q
    /// and divides by `delta` to obtain the real-valued result.
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,

    /// CRT quotient polynomials (secret witnesses).
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
}

impl<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let BIT_D_NATIVE: u32> DecryptedSharesAggregationCkks<MAX_MSG_NON_ZERO_COEFFS, L, T, BIT_D_NATIVE> {
    pub fn new(
        configs: Configs<L>,
        expected_d_commitments: [Field; T + 1],
        decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
        party_ids: [Field; T + 1],
        u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
        crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
    ) -> Self {
        DecryptedSharesAggregationCkks {
            configs,
            expected_d_commitments,
            decryption_shares,
            party_ids,
            u_global,
            crt_quotients,
        }
    }

    /// Run all checks (asserts hold or the proof fails).
    pub fn execute(self) {
        // Step 0: Bind each party's shares to its C6 commitment.
        for party_idx in 0..(T + 1) {
            let computed = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
                self.decryption_shares[party_idx],
            );
            assert(computed == self.expected_d_commitments[party_idx], "d commitment mismatch");
        }

        // Step 1: Lagrange coefficients per CRT basis.
        let lagrange_coeffs = compute_all_lagrange_coeffs::<T, L>(self.configs.qis, self.party_ids);

        // Step 2: Interpolate u^{(l)} per basis.
        let u_crts = compute_crt_components::<MAX_MSG_NON_ZERO_COEFFS, L, T>(
            self.configs.qis,
            self.decryption_shares,
            lagrange_coeffs,
        );

        // Step 3: CRT glue: u^{(l)} + r^{(l)} * q_l = u_global for all l.
        // This IS the final binding: u_global is the public plaintext ring
        // element. No modular decode follows (CKKS decode is off-circuit).
        verify_crt_reconstruction::<MAX_MSG_NON_ZERO_COEFFS, L>(
            self.configs.qis,
            self.u_global,
            self.crt_quotients,
            u_crts,
        );
    }
}

/// In-lib sanity test: a 3-party (T=1), single-limb CKKS aggregation with a
/// known Shamir sharing reconstructs the shared value.
#[test]
fn test_ckks_aggregation_reconstructs_shamir_secret() {
    // Modulus q = 97 (small prime). Secret polynomial value u = 42 (single
    // coefficient). Sharing polynomial f(x) = 42 + 5x mod 97: shares
    // f(1) = 47, f(2) = 52. Lagrange at 0 with x = [1, 2]:
    // L1 = 2, L2 = -1 -> 2*47 - 52 = 42. CRT trivial (single limb).
    let qis = [97];
    let configs = Configs::new(qis);

    let d1 = [Polynomial::new([47])];
    let d2 = [Polynomial::new([52])];
    let shares = [d1, d2];
    let party_ids = [1, 2];

    let expected_d_commitments = [
        compute_threshold_decryption_share_commitment::<1, 1, 59>(d1),
        compute_threshold_decryption_share_commitment::<1, 1, 59>(d2),
    ];

    let u_global = Polynomial::new([42]);
    let crt_quotients = [Polynomial::new([0])];

    let circuit: DecryptedSharesAggregationCkks<1, 1, 1, 59> = DecryptedSharesAggregationCkks::new(
        configs,
        expected_d_commitments,
        shares,
        party_ids,
        u_global,
        crt_quotients,
    );
    circuit.execute();
}
