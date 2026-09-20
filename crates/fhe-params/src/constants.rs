// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Constants for BFV presets
//!
//! This module contains all hardcoded values used in preset definitions.
//! Centralizing these values makes it easier to maintain and update presets.

/// Insecure preset constants (degree 128) - DO NOT USE IN PRODUCTION
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
    pub const NUM_PARTIES: u128 = 20; // real - used in the search default

    /// Threshold BFV parameters
    pub mod threshold {
        pub const PLAINTEXT_MODULUS: u64 = 1000000;
        pub const MODULI: &[u64] = &[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001];
        pub const ERROR1_VARIANCE: &str = "17723039943798878305460955570711717478400";
    }

    /// DKG parameters
    pub mod dkg {
        pub const PLAINTEXT_MODULUS: u64 = 288230376164294657;
        pub const MODULI: &[u64] = &[0x1000000000024001, 0x1000000000054001];
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

/// Common search defaults shared across presets
/// Search defaults for the SecureThreshold8192 preset (production scale).
/// The insecure preset uses its own smaller values (see `insecure_search_defaults`)
/// so that the smudging bounds baked into the insecure circuit configs remain valid.
pub mod search_defaults {
    pub const B: u128 = 20;
    pub const B_CHI: u128 = 1;
    pub const SEARCH_N: u128 = 20;
    pub const SEARCH_K: u128 = 1000000;
    pub const SEARCH_Z: u128 = 1000000;
}

/// Search defaults for the insecure preset (test-only, small scale).
/// These match the parameters used when `circuits/lib/src/configs/insecure/` was generated,
/// so the compiled `E_SM_BIT_SECRET` / `SHARE_ENCRYPTION_*` bounds remain consistent at runtime.
pub mod insecure_search_defaults {
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
    pub const SEARCH_N: u128 = 20;
    pub const SEARCH_K: u128 = 1000;
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
    /// Default secure security parameter (λ) for the 8192 presets.
    pub const DEFAULT_SECURE_LAMBDA: usize = 45;
    /// Statistical security parameter (λ) for the 16384 presets.
    pub const DEFAULT_SECURE_16384_LAMBDA: usize = 31;

    /// Multiplicative depth for the insecure preset.
    pub const INSECURE_MULT_DEPTH: u32 = 3;
    /// Multiplicative depth for secure-8192 preset (no l-BFV support).
    pub const SECURE_8192_MULT_DEPTH: u32 = 0;
    /// Multiplicative depth for secure-16384 preset.
    ///
    /// Depth 3 is feasible with the regenerated (larger-q) parameters.
    pub const SECURE_16384_MULT_DEPTH: u32 = 3;
}
