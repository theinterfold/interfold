// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV parameter profiles. Both use a prime plaintext modulus `t ≡ 1 (mod 2N)`, so every
//! design can use SIMD slots, and every non-zero value has an inverse mod `t`.

use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use fhe_math::zq::primes::generate_prime;
use std::sync::Arc;

/// Largest supported prime size. fhe.rs requires ciphertext moduli below 2^62.
const MAX_PRIME_BITS: usize = 62;
/// Target prime size: about the size that `search_params` picks for these depths.
const TARGET_PRIME_BITS: f64 = 58.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// N = 1024, t = 12289. Fast and NOT secure: use it for tests and quick runs.
    Toy,
    /// N = 16384, t = 65537. The ring size of the secure l-BFV preset.
    Demo,
}

impl Profile {
    pub fn degree(self) -> usize {
        match self {
            Profile::Toy => 1024,
            Profile::Demo => 16384,
        }
    }

    pub fn plaintext_modulus(self) -> u64 {
        match self {
            Profile::Toy => 12289,
            Profile::Demo => 65537,
        }
    }

    /// Upper bound on log2(q) for 128-bit security at this degree, as `search_params` computes it
    /// (`log2(B) + (N - 75) / 37.5` with B = 20). The toy profile is insecure by design.
    pub fn security_limit_bits(self) -> Option<f64> {
        match self {
            Profile::Toy => None,
            Profile::Demo => Some(20f64.log2() + (16384.0 - 75.0) / 37.5),
        }
    }

    /// The ciphertext modulus size that a circuit of `depth` ct×ct products needs.
    ///
    /// `search_params` (t = 65537, N = 16384, 20 parties, λ = 31, z = 2) gives 221.6 bits at
    /// depth 2 and 49.3 more bits for each further level, up to depth 8. The bound includes the
    /// threshold smudging noise, so one-party runs keep a large spare noise budget.
    pub fn required_log2_q(depth: u32) -> f64 {
        221.6 + 49.3 * f64::from(depth.saturating_sub(2))
    }

    /// Builds the parameters for a circuit of `depth` ct×ct products.
    pub fn build(self, depth: u32) -> Arc<BfvParameters> {
        let required = Self::required_log2_q(depth);
        let count = ((required / TARGET_PRIME_BITS).ceil() as usize).max(5);
        let bits = ((required / count as f64).ceil() as usize + 1).min(MAX_PRIME_BITS);
        let degree = self.degree();
        let mut moduli = Vec::with_capacity(count);
        let mut upper = 1u64 << bits;
        for _ in 0..count {
            upper = generate_prime(bits, 2 * degree as u64, upper)
                .expect("each prime size has more NTT-friendly primes than the profiles use");
            moduli.push(upper);
        }
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(self.plaintext_modulus())
            .set_moduli(&moduli)
            .build_arc()
            .expect("the profile values are valid BFV parameters")
    }
}
