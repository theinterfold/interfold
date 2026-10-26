// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Constants for BFV presets
//!
//! This module contains all hardcoded values used in preset definitions.
//! Centralizing these values makes it easier to maintain and update presets.

/// Insecure preset constants (degree 64) - DO NOT USE IN PRODUCTION
///
/// The trBFV insecure preset (on-chain parameter set 0).
pub mod insecure_64 {
    pub const DEGREE: usize = 64;
    pub const NUM_PARTIES: u128 = 19; // fake - not used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 17000000;
        pub const MODULI: &[u64] = &[0x0000000007fffd81, 0x0000000007fff801, 0x0000000007fff781];
        /// ⌊B_Enc(B_Enc+1)/3⌋ for B_Enc = 194560 (uniform e_1).
        pub const ERROR1_VARIANCE: &str = "12617929386";
        pub const ERROR1_VARIANCE_BIGUINT: u64 = 12617929386;
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 134217089;
        pub const MODULI: &[u64] = &[0x000000001fffba01, 0x000000001fffc081];
        pub const ERROR1_VARIANCE: &str = "10";
        pub const VARIANCE: u32 = 10;
    }
}

/// Insecure l-BFV preset constants (degree 128) - DO NOT USE IN PRODUCTION
///
/// The insecure preset of the l-BFV protocol path (on-chain parameter set 4).
pub mod insecure {
    pub const DEGREE: usize = 128;
    pub const NUM_PARTIES: u128 = 19;

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 100;
        pub const MODULI: &[u64] = &[
            0x00ff_ffff_ffff_c601,
            0x00ff_ffff_ffff_c301,
            0x00ff_ffff_ffff_a501,
        ];
        pub const ERROR1_VARIANCE: &str = "50471587840";
    }

    /// Encrypted-share BFV parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 72_057_594_037_913_089;
        pub const MODULI: &[u64] = &[0x01ff_ffff_ffff_9001, 0x01ff_ffff_ffff_9501];
        pub const ERROR1_VARIANCE: &str = "10";
        pub const VARIANCE: u32 = 10;
    }
}

/// Insecure SIMD preset constants (degree 128, t = 257) - DO NOT USE IN PRODUCTION
///
/// `PLAINTEXT_MODULUS` is prime and 1 mod 2N, so the plaintext ring splits into N SIMD slots.
/// The ciphertext moduli and the error variance equal the insecure ones, and so do the DKG
/// parameters (re-exported). `scripts/check-committee.sh` reads the literals below, so they stay
/// spelled out.
pub mod insecure_simd {
    pub use super::insecure::dkg;

    pub const DEGREE: usize = 128;
    /// Largest committee that satisfies the depth-3 noise bound at this plaintext modulus.
    pub const NUM_PARTIES: u128 = 9;

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 257;
        pub const MODULI: &[u64] = &[
            0x00ff_ffff_ffff_c601,
            0x00ff_ffff_ffff_c301,
            0x00ff_ffff_ffff_a501,
        ];
        pub const ERROR1_VARIANCE: &str = "50471587840";
    }
}

/// Secure preset constants (degree 8192) - PRODUCTION READY
pub mod secure_8192 {
    pub const DEGREE: usize = 8192;
    pub const NUM_PARTIES: u128 = 20; // real - used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 17000000;
        pub const MODULI: &[u64] = &[0x0800000000db4001, 0x0800000000d54001, 0x0800000000cbc001];
        pub const ERROR1_VARIANCE: &str = "17723039943798878305460955570711717478400";
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 576460752317792257;
        pub const MODULI: &[u64] = &[0x2000000000104001, 0x200000000013c001];
        pub const ERROR1_VARIANCE: &str = "10";
    }
}

/// Secure preset constants (degree 16384), available for generation but not enabled in the
/// current deployment matrix. The runtime
/// `SmudgingBoundCalculator` enforces `2*(B_C + n*B_sm) < Delta = floor(Q/t)`;
/// these 16384 parameters were regenerated with the multiplicative-depth-aware
/// search (Prop. 20 recursion) and support `mult_depth` 0-3 at runtime.
pub mod secure_16384 {
    pub const DEGREE: usize = 16384;
    pub const NUM_PARTIES: u128 = 20; // real - used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 1000;
        pub const MODULI: &[u64] = &[
            0x00040000009f0001,
            0x00040000008a0001,
            0x0004000000800001,
            0x00040000007e0001,
            0x0004000000750001,
        ];
        pub const ERROR1_VARIANCE: &str = "264093875047547791978479834453333";
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 1125899917262849;
        pub const MODULI: &[u64] = &[0x0010000000060001, 0x00100000000f0001];
        pub const ERROR1_VARIANCE: &str = "10";
    }
}

/// Secure SIMD preset constants (degree 16384, plaintext modulus 65537), the l-BFV preset for
/// multiplicative depth 3 with 16384 SIMD slots.
///
/// `PLAINTEXT_MODULUS` is prime and 1 mod 2N, so the plaintext ring splits into N SIMD slots. The
/// parameters come from `search_params --d 16384 --n 20 --k 65537 --z 3 --lambda 31 --b 20
/// --b-chi 1 --mult-depth 3`, the inputs in `secure_16384_simd_search_defaults`. The set has 5
/// primes of 56 bits, log2(q) = 276, well below the RLWE limit of this degree. One set covers every
/// committee up to n = 20. The DKG set follows the search: its plaintext modulus is the largest
/// prime of the threshold set and its two 58-bit moduli hold the shares.
pub mod secure_16384_simd {
    pub const DEGREE: usize = 16384;
    pub const NUM_PARTIES: u128 = 20; // real - used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 65537;
        pub const MODULI: &[u64] = &[
            0x00800000009d0001,
            0x0080000000850001,
            0x0080000000770001,
            0x0080000000730001,
            0x00800000005e0001,
        ];
        pub const ERROR1_VARIANCE: &str = "264093875047547801360979058141866";
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 36028797029253121;
        pub const MODULI: &[u64] = &[0x02000000002b0001, 0x02000000003a0001];
        pub const ERROR1_VARIANCE: &str = "10";
    }
}

/// Common search defaults shared across presets
/// Search defaults for the SecureThreshold8192 preset (production scale).
/// The insecure presets use their own smaller values (see `insecure_search_defaults`)
/// so that the smudging bounds baked into the insecure circuit configs remain valid.
pub mod search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 20;
    pub const SEARCH_K: u128 = 17000000;
    pub const SEARCH_Z: u128 = 100000;
}

/// Search defaults for the InsecureThreshold64 preset (test-only, small scale).
/// These match the parameters used when `circuits/lib/src/configs/insecure_64/` was generated,
/// so the compiled `E_SM_BIT_SECRET` / `SHARE_ENCRYPTION_*` bounds remain consistent at runtime.
pub mod insecure_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 19;
    pub const SEARCH_K: u128 = 17000000;
    pub const SEARCH_Z: u128 = 100000;
}

/// Search defaults for the insecure l-BFV preset (test-only, small scale).
/// These match the parameters used when `circuits/lib/src/configs/insecure/` was generated,
/// so the compiled `E_SM_BIT_SECRET` / `SHARE_ENCRYPTION_*` bounds remain consistent at runtime.
pub mod insecure_lbfv_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 19;
    pub const SEARCH_K: u128 = 100;
    pub const SEARCH_Z: u128 = 3;
}

/// Search defaults for the insecure SIMD preset (test-only, small scale).
/// `SEARCH_N` is the largest committee the depth-3 noise bound admits; the runtime uses the
/// real committee size.
pub mod insecure_simd_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 9;
    pub const SEARCH_K: u128 = 257;
    pub const SEARCH_Z: u128 = 3;
}

/// Search defaults for the SecureThreshold16384 preset (production scale).
/// `SEARCH_Z` is the number of summed ciphertexts (smudging `m`); the runtime
/// multiplicative depth is `SECURE_16384_MULT_DEPTH` (= 3).
pub mod secure_16384_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 20;
    pub const SEARCH_K: u128 = 1000;
    pub const SEARCH_Z: u128 = 3;
}

/// Search defaults for the SecureThreshold16384Simd preset (production scale).
/// `SEARCH_Z` is the number of summed ciphertexts (smudging `m`); the runtime multiplicative depth
/// is `SECURE_16384_SIMD_MULT_DEPTH` (= 3). `SEARCH_K` is the SIMD plaintext modulus.
pub mod secure_16384_simd_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 20;
    pub const SEARCH_K: u128 = 65537;
    pub const SEARCH_Z: u128 = 3;
}

/// Default values for BFV parameters
pub mod defaults {
    /// Default variance for BFV parameters when not explicitly set
    /// This is the standard default variance (and error1_variance) used in BFV
    /// when variance is not specified. Both variance() and error1_variance default to this value.
    pub const VARIANCE: usize = 10;

    /// Default insecure security parameter (λ).
    pub const DEFAULT_INSECURE_LAMBDA: usize = 2;
    /// Minimum statistical security parameter (λ) for secure presets.
    pub const MIN_SECURE_LAMBDA: usize = 31;
    /// Default secure security parameter (λ) for the 8192 presets.
    pub const DEFAULT_SECURE_LAMBDA: usize = 45;
    /// Statistical security parameter (λ) for the 16384 presets.
    pub const DEFAULT_SECURE_16384_LAMBDA: usize = 31;
    /// Statistical security parameter (λ) for the 16384 SIMD presets.
    pub const DEFAULT_SECURE_16384_SIMD_LAMBDA: usize = 31;

    /// Multiplicative depth for the insecure-64 preset (trBFV only, no l-BFV support).
    pub const INSECURE_64_MULT_DEPTH: u32 = 0;
    /// Multiplicative depth for the insecure l-BFV presets (insecure and insecure-simd).
    pub const INSECURE_MULT_DEPTH: u32 = 3;
    /// Multiplicative depth for secure-8192 preset (no l-BFV support).
    pub const SECURE_8192_MULT_DEPTH: u32 = 0;
    /// Multiplicative depth for secure-16384 preset.
    ///
    /// Depth 3 is feasible with the regenerated (larger-q) parameters.
    pub const SECURE_16384_MULT_DEPTH: u32 = 3;
    /// Multiplicative depth for the secure-16384-simd preset.
    pub const SECURE_16384_SIMD_MULT_DEPTH: u32 = 3;
}
