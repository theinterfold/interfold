// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::builder::build_pair_for_preset;
use crate::builder::{build_bfv_params_from_set, build_bfv_params_from_set_arc};
use crate::constants::{
    defaults::DEFAULT_INSECURE_LAMBDA,
    defaults::DEFAULT_SECURE_16384_LAMBDA,
    defaults::DEFAULT_SECURE_LAMBDA,
    defaults::INSECURE_512_MULT_DEPTH,
    defaults::SECURE_16384_MULT_DEPTH,
    defaults::SECURE_8192_MULT_DEPTH,
    insecure_512,
    insecure_search_defaults::{
        B as INSECURE_B, B_CHI as INSECURE_B_CHI, SEARCH_K as INSECURE_SEARCH_K,
        SEARCH_N as INSECURE_SEARCH_N, SEARCH_Z as INSECURE_SEARCH_Z,
    },
    search_defaults::{B, B_CHI, SEARCH_K, SEARCH_N, SEARCH_Z},
    secure_16384,
    secure_16384_search_defaults::{
        B as SECURE_16384_B, B_CHI as SECURE_16384_B_CHI, SEARCH_K as SECURE_16384_K,
        SEARCH_N as SECURE_16384_N, SEARCH_Z as SECURE_16384_Z,
    },
    secure_8192,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error as ThisError;

use fhe::bfv::BfvParameters;
use fhe::trbfv::Lambda;

/// BFV preset configurations for PVSS (Public Verifiable Secret Sharing)
///
/// In the PVSS protocol, two types of BFV parameters are needed:
///
/// **Threshold BFV Parameters**: Used for the main threshold encryption/decryption operations
/// (Phases 2-3-4). These are the parameters for the threshold public key that users encrypt with,
/// and for threshold decryption where T+1 parties collaborate to decrypt.
///
/// **DKG Parameters**: Used during Distributed Key Generation (Phases 0-1). Each ciphernode
/// generates a standard (non-threshold) BFV key-pair using these parameters. These keys are
/// used exclusively for encrypting secret shares during DKG, since the threshold public key
/// doesn't exist yet. After DKG completes, these keys are no longer needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum BfvPreset {
    /// Insecure threshold BFV parameters (degree 512) - DO NOT USE IN PRODUCTION
    ///
    /// Used for threshold encryption (GRECO) and threshold decryption operations.
    /// These parameters define the threshold public key that data providers use to encrypt inputs.
    InsecureThreshold512,
    /// Insecure DKG parameters (degree 512) - DO NOT USE IN PRODUCTION
    ///
    /// Used during Phase 0-1 (BFV Key Setup and DKG) where each ciphernode generates
    /// a standard BFV key-pair to encrypt secret shares. These are temporary keys used
    /// only during the key generation process.
    InsecureDkg512,
    /// Secure threshold BFV parameters (degree 8192) - PRODUCTION READY
    ///
    /// Used for threshold encryption (GRECO) and threshold decryption operations.
    /// These parameters define the threshold public key that data providers use to encrypt inputs.
    #[default]
    SecureThreshold8192,
    /// Secure DKG parameters (degree 8192) - PRODUCTION READY
    ///
    /// Used during Phase 0-1 (BFV Key Setup and DKG) where each ciphernode generates
    /// a standard BFV key-pair to encrypt secret shares. These are temporary keys used
    /// only during the key generation process.
    SecureDkg8192,
    /// Secure threshold BFV parameters (degree 16384), enabled on Sepolia and local chains.
    ///
    /// Used for threshold encryption (GRECO) and threshold decryption operations with
    /// multiplicative depth up to 3 (l-BFV support; the regenerated constants satisfy
    /// the runtime `2*(B_C + n*B_sm) < Delta` correctness budget at depth 3). These
    /// parameters define the threshold public key that data providers use to encrypt inputs.
    SecureThreshold16384,
    /// Secure DKG parameters (degree 16384), enabled on Sepolia and local chains.
    ///
    /// Used during Phase 0-1 (BFV Key Setup and DKG) where each ciphernode generates
    /// a standard BFV key-pair to encrypt secret shares. These are temporary keys used
    /// only during the key generation process.
    SecureDkg16384,
}

impl BfvPreset {
    /// Convert an on-chain `ParamSet` enum value (uint8) to the corresponding
    /// threshold `BfvPreset`. Returns `None` for unknown values.
    pub fn from_on_chain_param_set(value: u8) -> Option<Self> {
        match value {
            0 => Some(BfvPreset::InsecureThreshold512),
            1 => Some(BfvPreset::SecureThreshold8192),
            2 => Some(BfvPreset::SecureThreshold16384),
            _ => None,
        }
    }
}

/// Default BFV preset used for local development and tests.
///
/// Production code that needs a chain-bound preset must select it explicitly from the active
/// protocol configuration. Use [`default_param_set()`] or `BfvParamSet::from(DEFAULT_BFV_PRESET)`
/// only when a fast local default is acceptable.
pub const DEFAULT_BFV_PRESET: BfvPreset = BfvPreset::InsecureThreshold512;

/// Returns the default BFV parameter set (same as `DEFAULT_BFV_PRESET` converted to [`BfvParamSet`]).
///
/// Convenience for crates that need a [`BfvParamSet`] without depending on config.
pub fn default_param_set() -> BfvParamSet {
    DEFAULT_BFV_PRESET.into()
}

/// Parameter type for BFV presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterType {
    /// Threshold BFV (TRBFV) parameters
    THRESHOLD,
    /// DKG parameters (BFV)
    DKG,
}

/// Security tier for BFV presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityTier {
    /// Insecure security tier
    INSECURE,
    /// Secure security tier
    SECURE,
}

impl SecurityTier {
    /// Config path segment for Noir (e.g. `configs::{}::threshold`).
    pub fn as_config_str(self) -> &'static str {
        match self {
            SecurityTier::INSECURE => "insecure",
            SecurityTier::SECURE => "secure",
        }
    }
}

impl core::str::FromStr for SecurityTier {
    type Err = PresetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "insecure" => Ok(Self::INSECURE),
            "secure" => Ok(Self::SECURE),
            _ => Err(PresetError::UnknownPreset(s.to_string())),
        }
    }
}

/// Metadata describing a BFV preset configuration
///
/// This struct contains high-level information about a preset, including
/// its security properties and basic parameter dimensions.
#[derive(Debug, Clone, Copy)]
pub struct PresetMetadata {
    /// The canonical name of the preset (e.g., "INSECURE_THRESHOLD_512")
    pub name: &'static str,
    /// LWE dimension (d) - the degree of the polynomial ring, must be a power of 2
    ///
    /// This determines the size of the polynomial ring R_q = Z_q[X]/(X^d + 1).
    /// Common values are 512, 1024, 2048, 4096, 8192, etc.
    pub degree: usize,
    /// Number of moduli (l) - the number of moduli used in the ciphertext space
    ///
    /// This determines the size of the ciphertext space.
    pub num_moduli: usize,
    /// Number of parties (n) - the number of ciphernodes in the system supported by
    /// the preset.
    ///
    /// This affects the security analysis and noise bounds.
    pub num_parties: u128,
    /// Statistical security parameter λ (negl(λ) = 2^{-λ})
    ///
    /// Higher values provide stronger security guarantees but may require
    /// larger parameters. Typically 80 for secure presets, 2 for insecure.
    pub lambda: usize,
    /// Parameter type (DKG (BFV) / Threshold (trBFV)).
    pub parameter_type: ParameterType,
    /// Security tier (e.g. for Noir `configs::{}::threshold`). Use [`SecurityTier::as_config_str`] for the path segment.
    pub security: SecurityTier,
}

/// Default search parameters for BFV parameter generation
///
/// These values are used when searching for optimal BFV parameters using
/// the search algorithm. They define the constraints and
/// requirements for parameter selection.
///
/// See `search::bfv::BfvSearchConfig` for more details.
#[derive(Debug, Clone, Copy)]
pub struct PresetSearchDefaults {
    /// Number of parties (n) - the number of ciphernodes in the system supported by
    /// the preset.
    ///
    /// This parameter affects the security analysis and noise bounds.
    pub n: u128,
    /// Number of fresh ciphertext additions z
    ///
    /// Note that the BFV plaintext modulus k will be defined as k = z.
    /// This is also equal to k_plain_eff in the search result.
    pub z: u128,
    /// Plaintext modulus k (plaintext space)
    ///
    /// The modulus for the plaintext space. Typically set equal to z.
    pub k: u128,
    /// Statistical Security parameter λ (negl(λ) = 2^{-λ})
    ///
    /// Higher values provide stronger security guarantees but may require
    /// larger parameters. Typically 80 for secure presets, 2 for insecure.
    pub lambda: u32,
    /// Bound B on the error distribution ψ
    ///
    /// Used to generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    /// This bound is used in security analysis equations.
    pub b: u128,
    /// Bound B_χ on the distribution χ
    ///
    /// Used to generate the secret key sk_i of each party i.
    /// This bound is used in security analysis equations.
    pub b_chi: u128,
    /// Multiplicative depth for l-BFV smudging noise computation.
    ///
    /// Set to 0 for presets without l-BFV support (insecure, secure-8192).
    /// Set to 3 for secure-16384.
    pub mult_depth: u32,
}

#[derive(ThisError, Debug)]
pub enum PresetError {
    #[error("Unknown preset: {0}")]
    UnknownPreset(String),
    #[error("Preset does not define a Threshold (trBFV) / DKG (BFV) pair: {0}")]
    MissingPair(&'static str),
    #[error("Preset lambda is not secure: {0}")]
    InsecureLambda(String),
}

/// Serializable smudging security level, mirroring [`fhe::trbfv::Lambda`].
///
/// `Lambda` is a foreign type without `serde` support, so requests that travel over the
/// wire (e.g. `GenPkShareAndSkSssRequest`) carry this instead and reconstruct the real
/// [`Lambda`] at the point of use via [`LambdaConfig::into_lambda`]. The `Secure`/`Insecure`
/// distinction is preserved across (de)serialization so the security tier chosen upstream
/// from a [`BfvPreset`] is faithfully enforced downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LambdaConfig {
    /// Production security level; validated against `MIN_SECURE_LAMBDA` by [`Lambda::secure`].
    Secure(usize),
    /// Deliberately weak level for fast testing; see [`Lambda::insecure`].
    Insecure(usize),
}

impl LambdaConfig {
    /// Reconstruct the real [`Lambda`]. `Secure` variants fail if the value is below the
    /// library's secure minimum.
    pub fn into_lambda(self) -> Result<Lambda, PresetError> {
        match self {
            LambdaConfig::Secure(lambda) => {
                Lambda::secure(lambda).map_err(|e| PresetError::InsecureLambda(e.to_string()))
            }
            LambdaConfig::Insecure(lambda) => Ok(Lambda::insecure(lambda)),
        }
    }
}

/// A complete BFV parameter set definition
///
/// This struct contains all the values needed to construct a `BfvParameters`
/// instance. It represents a concrete set of cryptographic parameters for
/// building a BFV (Brakerski-Fan-Vercauteren) homomorphic encryption.
#[derive(Debug, Clone, Copy)]
pub struct BfvParamSet {
    /// LWE dimension (d) - the degree of the polynomial ring, must be a power of 2
    ///
    /// This determines the size of the polynomial ring R_q = Z_q[X]/(X^d + 1).
    /// Common values are 512, 1024, 2048, 4096, 8192, etc.
    pub degree: usize,
    /// Plaintext modulus (k) - the modulus for the plaintext space
    ///
    /// This defines the range of values that can be encrypted as plaintexts.
    /// Plaintexts are elements of the ring Z_k.
    pub plaintext_modulus: u64,
    /// Ciphertext moduli (q_i) - array of NTT-friendly primes for the ciphertext space
    ///
    /// These are the moduli used in the Chinese Remainder Theorem (CRT) representation
    /// of the ciphertext space. The product q = ∏q_i is the ciphertext modulus.
    /// Each prime must be NTT-friendly (typically 40-63 bits) for efficient operations.
    pub moduli: &'static [u64],
    /// Error1 variance (as decimal string) - variance of the encryption error distribution
    ///
    /// This is the variance of the error term e0 in the encryption process.
    /// If None, defaults to "10" (the standard default for BFV parameters).
    /// This value is used in noise analysis and security proofs.
    pub error1_variance: Option<&'static str>,
}

impl BfvParamSet {
    pub fn build(self) -> BfvParameters {
        build_bfv_params_from_set(self)
    }

    pub fn build_arc(self) -> Arc<BfvParameters> {
        build_bfv_params_from_set_arc(self)
    }
}

impl BfvPreset {
    pub const ALL: [BfvPreset; 6] = [
        BfvPreset::InsecureThreshold512,
        BfvPreset::InsecureDkg512,
        BfvPreset::SecureThreshold8192,
        BfvPreset::SecureDkg8192,
        BfvPreset::SecureThreshold16384,
        BfvPreset::SecureDkg16384,
    ];

    pub const PAIR_PRESETS: [BfvPreset; 3] = [
        BfvPreset::InsecureThreshold512,
        BfvPreset::SecureThreshold8192,
        BfvPreset::SecureThreshold16384,
    ];

    pub fn from_name(name: &str) -> Result<Self, PresetError> {
        let normalized = name.trim().to_ascii_uppercase();
        match normalized.as_str() {
            "INSECURE_THRESHOLD_512" => Ok(Self::InsecureThreshold512),
            "INSECURE_DKG_512" => Ok(Self::InsecureDkg512),
            "SECURE_THRESHOLD_8192" => Ok(Self::SecureThreshold8192),
            "SECURE_DKG_8192" => Ok(Self::SecureDkg8192),
            "SECURE_THRESHOLD_16384" => Ok(Self::SecureThreshold16384),
            "SECURE_DKG_16384" => Ok(Self::SecureDkg16384),
            _ => Err(PresetError::UnknownPreset(name.to_string())),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            BfvPreset::InsecureThreshold512 => "INSECURE_THRESHOLD_512",
            BfvPreset::InsecureDkg512 => "INSECURE_DKG_512",
            BfvPreset::SecureThreshold8192 => "SECURE_THRESHOLD_8192",
            BfvPreset::SecureDkg8192 => "SECURE_DKG_8192",
            BfvPreset::SecureThreshold16384 => "SECURE_THRESHOLD_16384",
            BfvPreset::SecureDkg16384 => "SECURE_DKG_16384",
        }
    }

    /// Parses `insecure`, `secure-8192`, `secure-16384`, or a preset λ into the threshold preset.
    pub fn from_security_config_name(name: &str) -> Result<Self, PresetError> {
        let s = name.trim();
        if let Ok(lambda) = s.parse::<usize>() {
            return Self::PAIR_PRESETS
                .iter()
                .copied()
                .find(|p| p.metadata().lambda == lambda)
                .ok_or_else(|| PresetError::UnknownPreset(format!("lambda {lambda}")));
        }
        match s.to_ascii_lowercase().as_str() {
            "insecure" => Ok(Self::InsecureThreshold512),
            "secure-8192" => Ok(Self::SecureThreshold8192),
            "secure-16384" => Ok(Self::SecureThreshold16384),
            _ => Err(PresetError::UnknownPreset(name.to_string())),
        }
    }

    pub fn list() -> Vec<&'static str> {
        Self::ALL.iter().map(BfvPreset::name).collect()
    }

    pub fn list_pairs() -> Vec<&'static str> {
        Self::PAIR_PRESETS.iter().map(BfvPreset::name).collect()
    }

    pub fn supports_pair(&self) -> bool {
        Self::PAIR_PRESETS.contains(self)
    }

    /// Resolve an exact threshold parameter tuple to the preset whose circuit statement uses it.
    pub fn from_threshold_parameters(
        degree: usize,
        plaintext_modulus: u64,
        moduli: &[u64],
    ) -> Option<Self> {
        Self::PAIR_PRESETS.iter().copied().find(|preset| {
            let parameters = BfvParamSet::from(*preset);
            parameters.degree == degree
                && parameters.plaintext_modulus == plaintext_modulus
                && parameters.moduli == moduli
        })
    }

    /// Returns the DKG preset that pairs with this threshold preset.
    ///
    /// Used when you have a threshold preset (e.g. for encryption/decryption) and need
    /// the corresponding DKG parameters (e.g. for share encryption during key generation).
    /// Returns `None` when called on a DKG preset.
    pub fn dkg_counterpart(self) -> Option<BfvPreset> {
        match self {
            BfvPreset::InsecureThreshold512 => Some(BfvPreset::InsecureDkg512),
            BfvPreset::SecureThreshold8192 => Some(BfvPreset::SecureDkg8192),
            BfvPreset::SecureThreshold16384 => Some(BfvPreset::SecureDkg16384),
            BfvPreset::InsecureDkg512 | BfvPreset::SecureDkg8192 | BfvPreset::SecureDkg16384 => {
                None
            }
        }
    }

    /// Returns the threshold preset that pairs with this DKG preset.
    ///
    /// Used when you have a DKG preset (e.g. for share encryption during key generation) and need
    /// the corresponding threshold parameters (e.g. for encryption/decryption).
    /// Returns `None` when called on a threshold preset.
    pub fn threshold_counterpart(self) -> Option<BfvPreset> {
        match self {
            BfvPreset::InsecureDkg512 => Some(BfvPreset::InsecureThreshold512),
            BfvPreset::SecureDkg8192 => Some(BfvPreset::SecureThreshold8192),
            BfvPreset::SecureDkg16384 => Some(BfvPreset::SecureThreshold16384),
            BfvPreset::InsecureThreshold512
            | BfvPreset::SecureThreshold8192
            | BfvPreset::SecureThreshold16384 => None,
        }
    }

    pub fn metadata(&self) -> PresetMetadata {
        match self {
            BfvPreset::InsecureThreshold512 => PresetMetadata {
                name: self.name(),
                degree: insecure_512::DEGREE,
                num_moduli: insecure_512::threshold::MODULI.len(),
                num_parties: insecure_512::NUM_PARTIES,
                lambda: DEFAULT_INSECURE_LAMBDA,
                parameter_type: ParameterType::THRESHOLD,
                security: SecurityTier::INSECURE,
            },
            BfvPreset::InsecureDkg512 => PresetMetadata {
                name: self.name(),
                degree: insecure_512::DEGREE,
                num_moduli: insecure_512::dkg::MODULI.len(),
                num_parties: insecure_512::NUM_PARTIES,
                lambda: DEFAULT_INSECURE_LAMBDA,
                parameter_type: ParameterType::DKG,
                security: SecurityTier::INSECURE,
            },
            BfvPreset::SecureThreshold8192 => PresetMetadata {
                name: self.name(),
                degree: secure_8192::DEGREE,
                num_moduli: secure_8192::threshold::MODULI.len(),
                num_parties: secure_8192::NUM_PARTIES,
                lambda: DEFAULT_SECURE_LAMBDA,
                parameter_type: ParameterType::THRESHOLD,
                security: SecurityTier::SECURE,
            },
            BfvPreset::SecureDkg8192 => PresetMetadata {
                name: self.name(),
                degree: secure_8192::DEGREE,
                num_moduli: secure_8192::dkg::MODULI.len(),
                num_parties: secure_8192::NUM_PARTIES,
                lambda: DEFAULT_SECURE_LAMBDA,
                parameter_type: ParameterType::DKG,
                security: SecurityTier::SECURE,
            },
            BfvPreset::SecureThreshold16384 => PresetMetadata {
                name: self.name(),
                degree: secure_16384::DEGREE,
                num_moduli: secure_16384::threshold::MODULI.len(),
                num_parties: secure_16384::NUM_PARTIES,
                lambda: DEFAULT_SECURE_16384_LAMBDA,
                parameter_type: ParameterType::THRESHOLD,
                security: SecurityTier::SECURE,
            },
            BfvPreset::SecureDkg16384 => PresetMetadata {
                name: self.name(),
                degree: secure_16384::DEGREE,
                num_moduli: secure_16384::dkg::MODULI.len(),
                num_parties: secure_16384::NUM_PARTIES,
                lambda: DEFAULT_SECURE_16384_LAMBDA,
                parameter_type: ParameterType::DKG,
                security: SecurityTier::SECURE,
            },
        }
    }

    /// Returns the security tier for this preset.
    pub fn security_tier(&self) -> SecurityTier {
        self.metadata().security
    }

    /// Returns the serializable smudging security level for this preset.
    ///
    /// Maps the preset's [`SecurityTier`] onto [`LambdaConfig`]: secure presets become
    /// `LambdaConfig::Secure`, insecure presets `LambdaConfig::Insecure`. Use this when the
    /// level must cross a serialization boundary; otherwise prefer [`BfvPreset::lambda`].
    pub fn lambda_config(&self) -> LambdaConfig {
        let meta = self.metadata();
        match meta.security {
            SecurityTier::SECURE => LambdaConfig::Secure(meta.lambda),
            SecurityTier::INSECURE => LambdaConfig::Insecure(meta.lambda),
        }
    }

    /// Builds the smudging security level ([`Lambda`]) for this preset.
    ///
    /// Secure presets validate that lambda meets the library's secure minimum; insecure
    /// presets opt into a deliberately weak lambda for fast testing. Mirrors the preset's
    /// [`SecurityTier`].
    pub fn lambda(&self) -> Result<Lambda, PresetError> {
        self.lambda_config().into_lambda()
    }

    /// Returns the base directory name for circuit artifacts (e.g. `"insecure"`, `"secure-8192"`).
    /// Threshold and DKG presets at the same degree share the same compiled circuits.
    pub fn artifacts_dir(&self) -> String {
        let meta = self.metadata();
        match self {
            BfvPreset::InsecureThreshold512 | BfvPreset::InsecureDkg512 => "insecure".to_string(),
            _ => format!("{}-{}", meta.security.as_config_str(), meta.degree),
        }
    }

    /// Returns the Noir config module name for this preset, e.g. `"insecure"`,
    /// `"secure-8192"`, `"secure-16384"`. Codegen/zk-cli routing must use
    /// this (not [`SecurityTier::as_config_str`]) so that each preset resolves to a distinct
    /// `configs::{module}` namespace.
    ///
    /// Identical to [`BfvPreset::artifacts_dir`]; the two names are kept in sync
    /// because artifacts and Noir configs are organized the same way.
    pub fn config_dir(&self) -> String {
        self.artifacts_dir()
    }

    /// Returns the valid Noir module name for this preset's generated configs.
    pub fn noir_config_module(&self) -> &'static str {
        match self {
            BfvPreset::InsecureThreshold512 | BfvPreset::InsecureDkg512 => "insecure",
            BfvPreset::SecureThreshold8192 | BfvPreset::SecureDkg8192 => "secure_8192",
            BfvPreset::SecureThreshold16384 | BfvPreset::SecureDkg16384 => "secure_16384",
        }
    }

    /// Returns the per-committee artifact directory: `"{preset}/{committee}"`.
    ///
    /// Use this at runtime so each committee size resolves to its own compiled artifacts
    /// (e.g. `"secure-8192/small"`, `"insecure/micro"`).
    pub fn artifacts_dir_for_committee<C: AsRef<str>>(&self, committee: C) -> String {
        format!("{}/{}", self.artifacts_dir(), committee.as_ref())
    }

    pub fn search_defaults(&self) -> Option<PresetSearchDefaults> {
        match self {
            BfvPreset::InsecureThreshold512 => Some(PresetSearchDefaults {
                n: INSECURE_SEARCH_N,
                k: INSECURE_SEARCH_K,
                z: INSECURE_SEARCH_Z,
                lambda: DEFAULT_INSECURE_LAMBDA as u32,
                b: INSECURE_B,
                b_chi: INSECURE_B_CHI,
                mult_depth: INSECURE_512_MULT_DEPTH,
            }),
            BfvPreset::SecureThreshold8192 => Some(PresetSearchDefaults {
                n: SEARCH_N,
                k: SEARCH_K,
                z: SEARCH_Z,
                lambda: DEFAULT_SECURE_LAMBDA as u32,
                b: B,
                b_chi: B_CHI,
                mult_depth: SECURE_8192_MULT_DEPTH,
            }),
            BfvPreset::SecureThreshold16384 => Some(PresetSearchDefaults {
                n: SECURE_16384_N,
                k: SECURE_16384_K,
                z: SECURE_16384_Z,
                lambda: DEFAULT_SECURE_16384_LAMBDA as u32,
                b: SECURE_16384_B,
                b_chi: SECURE_16384_B_CHI,
                mult_depth: SECURE_16384_MULT_DEPTH,
            }),
            _ => None,
        }
    }

    pub fn build_pair(&self) -> Result<(Arc<BfvParameters>, Arc<BfvParameters>), PresetError> {
        build_pair_for_preset(*self)
    }
}

impl From<BfvPreset> for BfvParamSet {
    fn from(value: BfvPreset) -> Self {
        match value {
            BfvPreset::InsecureThreshold512 => BfvParamSet {
                degree: insecure_512::DEGREE,
                moduli: insecure_512::threshold::MODULI,
                plaintext_modulus: insecure_512::threshold::PLAINTEXT_MODULUS,
                error1_variance: Some(insecure_512::threshold::ERROR1_VARIANCE),
            },
            BfvPreset::InsecureDkg512 => BfvParamSet {
                degree: insecure_512::DEGREE,
                moduli: insecure_512::dkg::MODULI,
                plaintext_modulus: insecure_512::dkg::PLAINTEXT_MODULUS,
                error1_variance: Some(insecure_512::dkg::ERROR1_VARIANCE),
            },
            BfvPreset::SecureThreshold8192 => BfvParamSet {
                degree: secure_8192::DEGREE,
                plaintext_modulus: secure_8192::threshold::PLAINTEXT_MODULUS,
                moduli: secure_8192::threshold::MODULI,
                error1_variance: Some(secure_8192::threshold::ERROR1_VARIANCE),
            },
            BfvPreset::SecureDkg8192 => BfvParamSet {
                degree: secure_8192::DEGREE,
                plaintext_modulus: secure_8192::dkg::PLAINTEXT_MODULUS,
                moduli: secure_8192::dkg::MODULI,
                error1_variance: Some(secure_8192::dkg::ERROR1_VARIANCE),
            },
            BfvPreset::SecureThreshold16384 => BfvParamSet {
                degree: secure_16384::DEGREE,
                plaintext_modulus: secure_16384::threshold::PLAINTEXT_MODULUS,
                moduli: secure_16384::threshold::MODULI,
                error1_variance: Some(secure_16384::threshold::ERROR1_VARIANCE),
            },
            BfvPreset::SecureDkg16384 => BfvParamSet {
                degree: secure_16384::DEGREE,
                plaintext_modulus: secure_16384::dkg::PLAINTEXT_MODULUS,
                moduli: secure_16384::dkg::MODULI,
                error1_variance: Some(secure_16384::dkg::ERROR1_VARIANCE),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{insecure_512, secure_16384, secure_16384_search_defaults, secure_8192};

    #[test]
    fn from_name_accepts_all_presets() {
        for preset in BfvPreset::ALL {
            let parsed = BfvPreset::from_name(preset.name()).expect("preset should parse");
            assert_eq!(parsed, preset);
        }
    }

    #[test]
    fn threshold_parameter_tuple_resolves_only_exact_supported_presets() {
        for preset in BfvPreset::PAIR_PRESETS {
            let parameters = BfvParamSet::from(preset);
            assert_eq!(
                BfvPreset::from_threshold_parameters(
                    parameters.degree,
                    parameters.plaintext_modulus,
                    parameters.moduli,
                ),
                Some(preset)
            );
        }

        let dkg = BfvParamSet::from(BfvPreset::InsecureDkg512);
        assert_eq!(
            BfvPreset::from_threshold_parameters(dkg.degree, dkg.plaintext_modulus, dkg.moduli,),
            None
        );

        let threshold = BfvParamSet::from(BfvPreset::InsecureThreshold512);
        let mut changed_moduli = threshold.moduli.to_vec();
        changed_moduli[0] ^= 1;
        assert_eq!(
            BfvPreset::from_threshold_parameters(
                threshold.degree,
                threshold.plaintext_modulus,
                &changed_moduli,
            ),
            None
        );
    }

    #[test]
    fn build_pair_matches_expected_params() {
        let (threshold, dkg) = BfvPreset::InsecureThreshold512.build_pair().unwrap();
        assert_eq!(threshold.degree(), insecure_512::DEGREE);
        assert_eq!(
            threshold.plaintext(),
            insecure_512::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(threshold.moduli(), insecure_512::threshold::MODULI);
        assert_eq!(dkg.degree(), insecure_512::DEGREE);
        assert_eq!(dkg.plaintext(), insecure_512::dkg::PLAINTEXT_MODULUS);
        assert_eq!(dkg.moduli(), insecure_512::dkg::MODULI);

        let (threshold, dkg) = BfvPreset::SecureThreshold8192.build_pair().unwrap();
        assert_eq!(threshold.degree(), secure_8192::DEGREE);
        assert_eq!(
            threshold.plaintext(),
            secure_8192::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(threshold.moduli(), secure_8192::threshold::MODULI);
        assert_eq!(dkg.degree(), secure_8192::DEGREE);
        assert_eq!(dkg.plaintext(), secure_8192::dkg::PLAINTEXT_MODULUS);
        assert_eq!(dkg.moduli(), secure_8192::dkg::MODULI);

        let (threshold, dkg) = BfvPreset::SecureThreshold16384.build_pair().unwrap();
        assert_eq!(threshold.degree(), secure_16384::DEGREE);
        assert_eq!(
            threshold.plaintext(),
            secure_16384::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(threshold.moduli(), secure_16384::threshold::MODULI);
        assert_eq!(dkg.degree(), secure_16384::DEGREE);
        assert_eq!(dkg.plaintext(), secure_16384::dkg::PLAINTEXT_MODULUS);
        assert_eq!(dkg.moduli(), secure_16384::dkg::MODULI);
    }

    #[test]
    fn test_param_set_build() {
        let preset = BfvPreset::InsecureDkg512;
        let param_set: BfvParamSet = preset.into();

        assert_eq!(param_set.degree, insecure_512::DEGREE);
        assert_eq!(
            param_set.plaintext_modulus,
            insecure_512::dkg::PLAINTEXT_MODULUS
        );
        assert_eq!(param_set.moduli, insecure_512::dkg::MODULI);

        let params = param_set.build();
        assert_eq!(params.degree(), param_set.degree);
        assert_eq!(params.plaintext(), param_set.plaintext_modulus);
        assert_eq!(params.moduli(), param_set.moduli);
    }

    #[test]
    fn test_param_set_build_arc() {
        let preset = BfvPreset::SecureDkg8192;
        let param_set: BfvParamSet = preset.into();

        let params = param_set.build_arc();
        assert_eq!(params.degree(), param_set.degree);
        assert_eq!(params.plaintext(), param_set.plaintext_modulus);
        assert_eq!(params.moduli(), param_set.moduli);
    }

    #[test]
    fn test_metadata_values() {
        let insecure = BfvPreset::InsecureThreshold512;
        let metadata = insecure.metadata();
        assert_eq!(metadata.degree, insecure_512::DEGREE);
        assert_eq!(metadata.num_parties, insecure_512::NUM_PARTIES);
        assert_eq!(metadata.lambda, DEFAULT_INSECURE_LAMBDA);

        let secure = BfvPreset::SecureThreshold8192;
        let metadata = secure.metadata();
        assert_eq!(metadata.degree, secure_8192::DEGREE);
        assert_eq!(metadata.num_parties, secure_8192::NUM_PARTIES);
        assert_eq!(metadata.lambda, DEFAULT_SECURE_LAMBDA);

        let secure16384 = BfvPreset::SecureThreshold16384;
        let metadata = secure16384.metadata();
        assert_eq!(metadata.degree, secure_16384::DEGREE);
        assert_eq!(metadata.num_parties, secure_16384::NUM_PARTIES);
        assert_eq!(metadata.lambda, DEFAULT_SECURE_16384_LAMBDA);
    }

    #[test]
    fn test_search_defaults() {
        let preset = BfvPreset::InsecureThreshold512;
        let defaults = preset.search_defaults().unwrap();
        assert_eq!(defaults.n, INSECURE_SEARCH_N);
        assert_eq!(defaults.k, INSECURE_SEARCH_K);
        assert_eq!(defaults.z, INSECURE_SEARCH_Z);
        assert_eq!(defaults.lambda, DEFAULT_INSECURE_LAMBDA as u32);

        let preset = BfvPreset::SecureThreshold8192;
        let defaults = preset.search_defaults().unwrap();
        assert_eq!(defaults.n, SEARCH_N);
        assert_eq!(defaults.k, SEARCH_K);
        assert_eq!(defaults.z, SEARCH_Z);
        assert_eq!(defaults.lambda, DEFAULT_SECURE_LAMBDA as u32);

        let preset = BfvPreset::SecureThreshold16384;
        let defaults = preset.search_defaults().unwrap();
        assert_eq!(defaults.n, secure_16384_search_defaults::SEARCH_N);
        assert_eq!(defaults.k, secure_16384_search_defaults::SEARCH_K);
        assert_eq!(defaults.z, secure_16384_search_defaults::SEARCH_Z);
        assert_eq!(defaults.lambda, DEFAULT_SECURE_16384_LAMBDA as u32);

        // DKG presets don't have search defaults
        assert!(BfvPreset::InsecureDkg512.search_defaults().is_none());
        assert!(BfvPreset::SecureDkg8192.search_defaults().is_none());
        assert!(BfvPreset::SecureDkg16384.search_defaults().is_none());
    }

    #[test]
    fn test_artifacts_dir() {
        assert_eq!(BfvPreset::InsecureThreshold512.artifacts_dir(), "insecure");
        assert_eq!(BfvPreset::InsecureDkg512.artifacts_dir(), "insecure");
        assert_eq!(
            BfvPreset::SecureThreshold8192.artifacts_dir(),
            "secure-8192"
        );
        assert_eq!(BfvPreset::SecureDkg8192.artifacts_dir(), "secure-8192");
        assert_eq!(
            BfvPreset::SecureThreshold16384.artifacts_dir(),
            "secure-16384"
        );
        assert_eq!(BfvPreset::SecureDkg16384.artifacts_dir(), "secure-16384");
    }
}
