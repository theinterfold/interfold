// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use crate::configs::secure_8192::threshold::{L as L_THRESHOLD, QIS as QIS_THRESHOLD};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for DKG secure_8192 preset
pub global N: u32 = 8192;
pub global L: u32 = 2;
pub global QIS: [Field; L] = [1152921504606994433, 1152921504607191041];
pub global PLAINTEXT_MODULUS: Field = 288230376164294657;
pub global Q_MOD_T: Field = 2508586813587465;
pub global Q_MOD_T_CENTERED: Field = 2508586813587465;
pub global DKG_ERROR_BOUND: Field = 20;

// Parity matrix is sized for the active committee and the secure-8192 threshold QIS;
// see `committee/{name}/parity_secure_8192.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE_8192 as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

pub global PK_BIT_PK: u32 = 60;

/************************************
-------------------------------------
share_computation chunk grid (l-BFV)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = 512;
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = 16;
pub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = 4;
pub global SHARE_COMPUTATION_N_BATCHES: u32 = 4;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 59;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;
pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);
pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 58;
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
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 59;
pub global SHARE_ENCRYPTION_CT0_BIT_R: u32 = 58;
pub global SHARE_ENCRYPTION_CT1_BIT_R: u32 = 13;
pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [362086980741092512, 639891851793844136];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [576460752303497216, 576460752303595520];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_CT0_R_BOUNDS: [Field; L] = [90521745189217441, 159972962955401129];
pub global SHARE_ENCRYPTION_CT1_R_BOUNDS: [Field; L] = [4096, 4096];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 288230376164294657;
pub global SHARE_ENCRYPTION_SCALED_QUOTIENT: bool = true;
pub global SHARE_ENCRYPTION_SCALE_K: Field = 4;
pub global SHARE_ENCRYPTION_DELTA: Field = 4611686018228027384;
pub global SHARE_ENCRYPTION_SMALL_D: [Field; L] = [199950348, 200736780];
pub global SHARE_ENCRYPTION_ALPHA: [Field; L] = [787847760345516, 1392310105343220];
pub global SHARE_ENCRYPTION_BETA: [Field; L] = [90521745189213345, 159972962955397033];
pub global SHARE_ENCRYPTION_BIT_Z: u32 = 52;
pub global SHARE_ENCRYPTION_T_POW_BIT: u32 = 58;
pub global SHARE_ENCRYPTION_T_GAP: Field = 12582913;
pub global SHARE_ENCRYPTION_T_GAP_BIT: u32 = 24;
pub global SHARE_ENCRYPTION_BIT_Q0: u32 = 26;
pub global SHARE_ENCRYPTION_Q0_OFFSET: Field = 4097;
pub global SHARE_ENCRYPTION_BIT_Q0_DIFF: u32 = 18;
pub global SHARE_ENCRYPTION_Q0_DIFF_OFFSET: Field = 8194;
pub global SHARE_ENCRYPTION_BIT_Q1: u32 = 14;
pub global SHARE_ENCRYPTION_Q1_OFFSET: Field = 4097;
pub global SHARE_ENCRYPTION_CONFIGS: ShareEncryptionConfigs<L> = ShareEncryptionConfigs::new(
    PLAINTEXT_MODULUS,
    Q_MOD_T,
    QIS,
    SHARE_ENCRYPTION_K0IS,
    SHARE_ENCRYPTION_PK_BOUNDS,
    SHARE_ENCRYPTION_E0_BOUND,
    SHARE_ENCRYPTION_E1_BOUND,
    SHARE_ENCRYPTION_U_BOUND,
    SHARE_ENCRYPTION_CT0_R_BOUNDS,
    SHARE_ENCRYPTION_CT1_R_BOUNDS,
    SHARE_ENCRYPTION_MSG_BOUND,
    SHARE_ENCRYPTION_SCALED_QUOTIENT,
    SHARE_ENCRYPTION_SMALL_D,
    SHARE_ENCRYPTION_ALPHA,
    SHARE_ENCRYPTION_BETA,
    SHARE_ENCRYPTION_Q0_OFFSET,
    SHARE_ENCRYPTION_Q0_DIFF_OFFSET,
    SHARE_ENCRYPTION_Q1_OFFSET,
);

/************************************
-------------------------------------
share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)
share_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)
-------------------------------------
************************************/

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 59;
pub global SHARE_DECRYPTION_BIT_AGG: u32 = 58;
