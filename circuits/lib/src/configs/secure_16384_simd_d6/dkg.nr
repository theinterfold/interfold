// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use crate::configs::secure_16384_simd_d6::threshold::{L as L_THRESHOLD, QIS as QIS_THRESHOLD};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for DKG secure_16384_simd_d6 preset
pub global N: u32 = 16384;
pub global L: u32 = 2;
pub global QIS: [Field; L] = [72057594038321153, 72057594040680449];
pub global PLAINTEXT_MODULUS: Field = 18014398525603841;
pub global Q_MOD_T: Field = 3956850668077065;
pub global Q_MOD_T_CENTERED: Field = 3956850668077065;
pub global DKG_ERROR_BOUND: Field = 20;

// Parity matrix is sized for the active committee and the secure-16384-simd-d6 threshold QIS;
// see `committee/{name}/parity_secure_16384_simd_d6.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE_16384_SIMD_D6 as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

pub global PK_BIT_PK: u32 = 56;

/************************************
-------------------------------------
share_computation chunk grid (l-BFV)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = if crate::configs::committee::active::N_PARTIES <= 4 {
    8192
} else {
    2048
};
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = N / SHARE_COMPUTATION_CHUNK_SIZE;
pub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = if SHARE_COMPUTATION_N_CHUNKS < 4 {
    SHARE_COMPUTATION_N_CHUNKS
} else {
    4
};
pub global SHARE_COMPUTATION_N_BATCHES: u32 =
    SHARE_COMPUTATION_N_CHUNKS / SHARE_COMPUTATION_CHUNKS_PER_BATCH;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 55;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;
pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);
pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 54;
pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 56;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 56;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 55;
pub global SHARE_ENCRYPTION_CT0_BIT_R: u32 = 53;
pub global SHARE_ENCRYPTION_CT1_BIT_R: u32 = 14;
pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [29936785055947517, 3261202686861492];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [36028797019160576, 36028797020340224];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_CT0_R_BOUNDS: [Field; L] = [7484196270652158, 815300672422069];
pub global SHARE_ENCRYPTION_CT1_R_BOUNDS: [Field; L] = [8192, 8192];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 18014398525603841;
pub global SHARE_ENCRYPTION_SCALED_QUOTIENT: bool = true;
pub global SHARE_ENCRYPTION_SCALE_K: Field = 4;
pub global SHARE_ENCRYPTION_DELTA: Field = 288230375906344952;
pub global SHARE_ENCRYPTION_SMALL_D: [Field; L] = [246939660, 256376844];
pub global SHARE_ENCRYPTION_ALPHA: [Field; L] = [1643898738635505, 179080251041376];
pub global SHARE_ENCRYPTION_BETA: [Field; L] = [7484196270643966, 815300672413877];
pub global SHARE_ENCRYPTION_BIT_Z: u32 = 52;
pub global SHARE_ENCRYPTION_T_POW_BIT: u32 = 54;
pub global SHARE_ENCRYPTION_T_GAP: Field = 16121857;
pub global SHARE_ENCRYPTION_T_GAP_BIT: u32 = 24;
pub global SHARE_ENCRYPTION_BIT_Q0: u32 = 26;
pub global SHARE_ENCRYPTION_Q0_OFFSET: Field = 8193;
pub global SHARE_ENCRYPTION_BIT_Q0_DIFF: u32 = 22;
pub global SHARE_ENCRYPTION_Q0_DIFF_OFFSET: Field = 16386;
pub global SHARE_ENCRYPTION_BIT_Q1: u32 = 15;
pub global SHARE_ENCRYPTION_Q1_OFFSET: Field = 8193;
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

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 55;
pub global SHARE_DECRYPTION_BIT_AGG: u32 = 54;
