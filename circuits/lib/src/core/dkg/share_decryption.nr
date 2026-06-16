// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment, compute_share_encryption_commitment_from_message,
};
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;

/// DKG share decryption and aggregation (C4a / C4b).
///
/// **Role:** Verify decrypted shares against C2 commitments and publish a commitment to the sum
/// over honest parties (run twice: sk path and e_sm path).
///
/// **Consumes:** Per-party share commitments from C2 (sk or e_sm branch).
///
/// **Produces:**
/// - C4a: `commit(agg_sk)` -> C6 (threshold share decryption).
/// - C4b: `commit(agg_e_sm)` -> C6 (threshold share decryption).
///
/// `BIT_MSG` hashes per-share plaintexts (aligned with C2). `BIT_AGG` hashes the CRT aggregate
/// (`compute_aggregated_shares_commitment`) and must match threshold C6 `BIT_SK` / `BIT_E_SM`.
pub struct ShareDecryption<let N: u32, let L: u32, let H: u32, let BIT_MSG: u32, let BIT_AGG: u32> {
    /// Expected commitments to the share polynomials, produced in C2a (for C4a) or C2b (for C4b)
    /// via commit_to_party_shares. Organised as [party_idx][mod_idx], covering all H honest
    /// parties and L CRT moduli.
    /// (public witnesses)
    expected_commitments: [[Field; L]; H],

    /// Decrypted share polynomials from H honest parties.
    /// Organised as [party_idx][mod_idx].
    /// (secret witnesses)
    decrypted_shares: [[Polynomial<N>; L]; H],
}

impl<let N: u32, let L: u32, let H: u32, let BIT_MSG: u32, let BIT_AGG: u32> ShareDecryption<N, L, H, BIT_MSG, BIT_AGG> {
    pub fn new(
        expected_commitments: [[Field; L]; H],
        decrypted_shares: [[Polynomial<N>; L]; H],
    ) -> Self {
        ShareDecryption { expected_commitments, decrypted_shares }
    }

    /// Verifies that each decrypted share matches its expected commitment from C2a/C2b.
    ///
    /// For each honest party and each CRT modulus, hashes the decrypted share polynomial
    /// and confirms it equals the commitment produced in C2 via commit_to_party_shares.
    /// Since commitments are binding, any substitution or tampering, claiming a different
    /// decrypted value or using the wrong secret key, will cause this assertion to fail.
    fn verify_commitments(self) {
        for party_idx in 0..H {
            for mod_idx in 0..L {
                // Reverse the share polynomial to match the commitment format used by C2's
                // commit_to_party_shares, which stores coefficients highest-degree-first.
                let share = self.decrypted_shares[party_idx][mod_idx];
                let mut reversed_coeffs: [Field; N] = [0; N];
                for i in 0..N {
                    reversed_coeffs[N - 1 - i] = share.coefficients[i];
                }
                assert(
                    compute_share_encryption_commitment_from_message::<N, BIT_MSG>(Polynomial::new(
                        reversed_coeffs,
                    ))
                        == self.expected_commitments[party_idx][mod_idx],
                    "Commitment mismatch",
                );
            }
        }
    }

    /// Aggregates all verified shares by summing coefficient-wise across honest parties.
    ///
    /// For each CRT modulus and each coefficient position, computes:
    ///   aggregated[mod_idx][coeff] = sum(decrypted_shares[party_idx][mod_idx][coeff])
    ///                                  for party_idx in 0..H
    ///
    /// No modular reduction is applied here each share coefficient is in [0, q_l) by C2 range
    /// checks, so the sum lies in [0, H*q_l) and fits in the circuit field. Reduction to [0, q_l)
    /// is performed by normalize_aggregated before committing.
    ///
    /// This reflects the threshold key construction: sk = sum(sk_i) for i in H.
    /// Each ciphernode now holds a share of this sum, used during threshold decryption in P4.
    fn compute_aggregated_shares(self) -> [Polynomial<N>; L] {
        let mut sum: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

        for mod_idx in 0..L {
            let mut coeffs = [0 as Field; N];
            for coeff_idx in 0..N {
                let mut total = 0 as Field;
                for party_idx in 0..H {
                    total =
                        total + self.decrypted_shares[party_idx][mod_idx].coefficients[coeff_idx];
                }
                coeffs[coeff_idx] = total;
            }
            sum[mod_idx] = Polynomial::new(coeffs);
        }

        sum
    }

    /// Executes the share decryption and aggregation circuit.
    ///
    /// Returns a commitment to the aggregated shares:
    /// - C4a: commit(agg_sk), consumed by C6 in P4
    /// - C4b: commit(agg_e_sm), consumed by C6 in P4
    ///
    /// `moduli` must be the threshold CRT moduli `[q_0, ..., q_{L-1}]`.
    /// They are used to reduce, reverse, and center the aggregated polynomials so that
    /// `compute_aggregated_shares_commitment` produces the same hash as C6's
    /// Rust witness (which operates on sk coefficients already reduced to `[0, q_l)`
    /// and then applies `.reverse()` and `.center(&qi)` before hashing).
    pub fn execute(self, moduli: [Field; L]) -> Field {
        // Step 1: Verify decrypted shares match expected C2 commitments.
        self.verify_commitments();

        // Step 2: Sum shares coefficient-wise per CRT limb.
        let aggregated = self.compute_aggregated_shares();

        // Step 3: Normalize to match C6's representation: reduce mod q, reverse, center.
        let normalized = normalize_aggregated::<N, L>(aggregated, moduli);

        // Step 4: Publish commitment to the aggregate (C6 input).
        compute_aggregated_shares_commitment::<N, L, BIT_AGG>(normalized)
    }
}

/// Normalize aggregated share polynomials to match C6's Rust witness representation.
///
/// C6 applies three transformations before hashing:
///   1. Reduce: coefficients to `[0, q_l)` (FHE `sk` is already reduced; C4 sums lie in `[0, H*q_l)`).
///   2. Reverse: coefficients are reordered highest-degree-first.
///   3. Center: each coefficient `c` is mapped to `c - q` when `c > (q-1)/2`,
///              so values lie in `[-(q-1)/2, (q-1)/2]` instead of `[0, q)`.
///
/// Reduction uses [`ModU128::reduce_mod`] (unconstrained quotient/remainder + in-circuit checks).
fn normalize_aggregated<let N: u32, let L: u32>(
    aggregated: [Polynomial<N>; L],
    moduli: [Field; L],
) -> [Polynomial<N>; L] {
    let mut normalized: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

    for mod_idx in 0..L {
        let poly = aggregated[mod_idx];
        let q = moduli[mod_idx];
        let half = (q - 1) / 2;

        let mut coeffs: [Field; N] = [0; N];
        for i in 0..N {
            // Reverse: position i gets the coefficient from N-1-i.
            let c = poly.coefficients[N - 1 - i];
            // c < H*q_l (sum of H shares); quotient < H (small) -- safe for ModU64.
            let reduced = ModU64::new(q as u64).reduce_mod(c);
            // Center: shift to [-(q-1)/2, (q-1)/2].
            // reduced < q < 2^62 and half < 2^61: u64 cast is sufficient, saves 22 gates.
            let centered = if (reduced as u64) > (half as u64) {
                reduced - q
            } else {
                reduced
            };
            coeffs[i] = centered;
        }
        normalized[mod_idx] = Polynomial::new(coeffs);
    }

    normalized
}
