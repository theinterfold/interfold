// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Constants for BFV presets
//!
//! This module contains all hardcoded values used in preset definitions.
//! Centralizing these values makes it easier to maintain and update presets.

/// Encryption scheme name used in the on-chain configuration identity.
pub const BFV_ENCRYPTION_SCHEME: &str = "fhe.rs:BFV";

/// Circuit statement domain used in current BFV configuration identities.
pub const INTERFOLD_BFV_VERSION: &str = "interfold-bfv-v5";

/// Insecure trBFV preset constants (degree 64) - DO NOT USE IN PRODUCTION
pub mod insecure_64 {
    pub const DEGREE: usize = 64;
    pub const NUM_PARTIES: u128 = 45; // fake - not used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 17000000;
        pub const MODULI: &[u64] = &[0x0000000007fffd81, 0x0000000007fff801, 0x0000000007fff781];
        /// ⌊B_Enc(B_Enc+1)/3⌋ for B_Enc = 460800 (uniform e_1).
        pub const ERROR1_VARIANCE: &str = "70779033600";
        pub const ERROR1_VARIANCE_BIGUINT: u64 = 70779033600;
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 134217089;
        pub const MODULI: &[u64] = &[0x000000001fffba01, 0x000000001fffc081];
        pub const ERROR1_VARIANCE: &str = "10";
        pub const VARIANCE: u32 = 10;
    }
}

/// Insecure preset constants (degree 128) - DO NOT USE IN PRODUCTION
///
/// Unlike `insecure_64`, which only has room for summation, these parameters support the
/// multiplication and relinearization that the l-BFV path needs.
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

/// Secure preset constants (degree 8192) - PRODUCTION READY
pub mod secure_8192 {
    pub const DEGREE: usize = 8192;
    pub const NUM_PARTIES: u128 = 45; // real - used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 17000000;
        pub const MODULI: &[u64] = &[0x0800000000db4001, 0x0800000000d54001, 0x0800000000cbc001];
        pub const ERROR1_VARIANCE: &str = "89722889715481821421179914794614285926400";
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
/// these 16384 parameters come from the multiplicative-depth-aware search (Prop. 20 recursion)
/// for the small committee and support `mult_depth` 0-3 at runtime. `Q` is about 2^312 and the
/// smudging bound about 2^288.6, both above the BN254 field, so the circuits carry them in two
/// field limbs (C2b smudging lift) or in U384 (wide C7).
pub mod secure_16384 {
    pub const DEGREE: usize = 16384;
    pub const NUM_PARTIES: u128 = 19; // real - used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 65537;
        pub const MODULI: &[u64] = &[
            0x0010000000960001,
            0x00100000007e0001,
            0x00100000006f0001,
            0x00100000006e0001,
            0x0010000000650001,
            0x0010000000500001,
        ];
        pub const ERROR1_VARIANCE: &str = "63980174197113950682582616558744119541760";
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 4503599637200897;
        pub const MODULI: &[u64] = &[0x0040000000120001, 0x00400000001d0001];
        pub const ERROR1_VARIANCE: &str = "10";
    }
}

/// Common search defaults shared across presets
/// Search defaults for the SecureThreshold8192 preset (production scale).
/// The insecure presets use their own smaller values (see `insecure_search_defaults` and
/// `insecure_128_search_defaults`) so that the smudging bounds baked into the insecure circuit
/// configs remain valid.
pub mod search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 45;
    pub const SEARCH_K: u128 = 17000000;
    pub const SEARCH_Z: u128 = 100000;
}

/// Search defaults for the InsecureThreshold64 preset (test-only, small scale).
pub mod insecure_search_defaults {
    /// Smallest prime bit-length for the insecure (toy ring) searches.
    pub const MIN_PRIME_BITS: u8 = 12;
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 45;
    pub const SEARCH_K: u128 = 17000000;
    pub const SEARCH_Z: u128 = 100000;
}

/// Search defaults for the degree-128 insecure presets (`insecure`; test-only, small scale).
/// These match the parameters used when `circuits/lib/src/configs/insecure/` was generated,
/// so the compiled `E_SM_BIT_SECRET` / `SHARE_ENCRYPTION_*` bounds remain consistent at runtime.
pub mod insecure_128_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 19;
    pub const SEARCH_K: u128 = 100;
    pub const SEARCH_Z: u128 = 3;
}

/// Search defaults for the SecureThreshold16384 preset (production scale).
/// `SEARCH_Z` is the number of summed ciphertexts (smudging `m`); the runtime
/// multiplicative depth is `SECURE_16384_MULT_DEPTH` (= 3).
pub mod secure_16384_search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 19;
    pub const SEARCH_K: u128 = 65537;
    pub const SEARCH_Z: u128 = 5000;
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
    pub const DEFAULT_SECURE_16384_LAMBDA: usize = 45;

    /// Multiplicative depth for the insecure-64 preset (summation only, no l-BFV support).
    pub const INSECURE_64_MULT_DEPTH: u32 = 0;
    /// Multiplicative depth for the degree-128 insecure presets.
    pub const INSECURE_MULT_DEPTH: u32 = 3;
    /// Multiplicative depth for secure-8192 preset (no l-BFV support).
    pub const SECURE_8192_MULT_DEPTH: u32 = 0;
    /// Multiplicative depth for secure-16384 preset.
    ///
    /// Depth 3 is feasible with the regenerated (larger-q) parameters.
    pub const SECURE_16384_MULT_DEPTH: u32 = 3;
}
