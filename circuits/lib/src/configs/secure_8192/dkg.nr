// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use crate::configs::secure_8192::threshold::{
    L as L_THRESHOLD, PK_GENERATION_BIT_E_SM as SHARE_COMPUTATION_E_SM_BIT_SECRET,
    QIS as QIS_THRESHOLD, THRESHOLD_SHARE_DECRYPTION_BIT_SK as SHARE_DECRYPTION_BIT_AGG,
};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for DKG secure_8192 preset
pub global N: u32 = 8192;
pub global L: u32 = 2;
/// Key bits packed into the largest threshold limb.
pub global PRF_KEY_BITS: u32 = 256;
pub global QIS: [Field; L] = [2305843009213177857, 2305843009213562881];
/// Twice the largest threshold modulus, so one coefficient holds a residue and one key bit.
pub global PLAINTEXT_MODULUS: Field = 576460752328589314;
pub global Q_MOD_T: Field = 10684499247595569;
pub global Q_MOD_T_CENTERED: Field = 10684499247595569;
pub global DKG_ERROR_BOUND: Field = 20;

// Parity matrix is sized for the active committee and the secure-8192 threshold QIS;
// see `committee/{name}/parity_secure_8192.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE_8192 as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters
pub global PK_BIT_PK: u32 = 60;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 59;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;
pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = 512;
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = 16;
pub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = 4;
pub global SHARE_COMPUTATION_N_BATCHES: u32 = 4;

pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 60;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 60;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 60;
pub global SHARE_ENCRYPTION_BIT_R1: u32 = 58;
pub global SHARE_ENCRYPTION_BIT_R2: u32 = 60;
pub global SHARE_ENCRYPTION_BIT_P1: u32 = 13;
pub global SHARE_ENCRYPTION_BIT_P2: u32 = 60;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [778756574448421609, 438911484683906823];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [1152921504605290496, 1152921504605700096];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_R1_LOW_BOUNDS: [Field; L] = [194689143620871635, 109727871175880207];
pub global SHARE_ENCRYPTION_R1_UP_BOUNDS: [Field; L] = [194689143620871635, 109727871175880207];
pub global SHARE_ENCRYPTION_R2_BOUNDS: [Field; L] = [1152921504605290496, 1152921504605700096];
pub global SHARE_ENCRYPTION_P1_BOUNDS: [Field; L] = [4096, 4096];
pub global SHARE_ENCRYPTION_P2_BOUNDS: [Field; L] = [1152921504605290496, 1152921504605700096];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 576460752328589313;

pub global SHARE_ENCRYPTION_CONFIGS: ShareEncryptionConfigs<L> = ShareEncryptionConfigs::new(
    PLAINTEXT_MODULUS,
    Q_MOD_T,
    QIS,
    SHARE_ENCRYPTION_K0IS,
    SHARE_ENCRYPTION_PK_BOUNDS,
    SHARE_ENCRYPTION_E0_BOUND,
    SHARE_ENCRYPTION_E1_BOUND,
    SHARE_ENCRYPTION_U_BOUND,
    SHARE_ENCRYPTION_R1_LOW_BOUNDS,
    SHARE_ENCRYPTION_R1_UP_BOUNDS,
    SHARE_ENCRYPTION_R2_BOUNDS,
    SHARE_ENCRYPTION_P1_BOUNDS,
    SHARE_ENCRYPTION_P2_BOUNDS,
    SHARE_ENCRYPTION_MSG_BOUND,
);

/************************************
-------------------------------------
share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)
share_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)
-------------------------------------
************************************/

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 59;
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
