// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use crate::configs::secure_16384::threshold::{
    L as L_THRESHOLD, PK_GENERATION_BIT_E_SM as SHARE_COMPUTATION_E_SM_BIT_SECRET,
    QIS as QIS_THRESHOLD, THRESHOLD_SHARE_DECRYPTION_BIT_SK as SHARE_DECRYPTION_BIT_AGG,
};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for DKG secure_16384 preset
pub global N: u32 = 16384;
pub global L: u32 = 2;
pub global QIS: [Field; L] = [4503599627763713, 4503599628353537];
pub global PLAINTEXT_MODULUS: Field = 1125899917262849;
pub global Q_MOD_T: Field = 554420383907848;
pub global Q_MOD_T_CENTERED: Field = 554420383907848;
pub global DKG_ERROR_BOUND: Field = 20;

// Parity matrix is sized for the active committee and the secure-16384 threshold QIS;
// see `committee/{name}/parity_secure_16384.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE_16384 as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters
pub global PK_BIT_PK: u32 = 52;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 51;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;
pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = 512;
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = 32;
pub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = 4;
pub global SHARE_COMPUTATION_N_BATCHES: u32 = 8;

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

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 52;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 52;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 51;
pub global SHARE_ENCRYPTION_BIT_R1: u32 = 50;
pub global SHARE_ENCRYPTION_BIT_R2: u32 = 52;
pub global SHARE_ENCRYPTION_BIT_P1: u32 = 14;
pub global SHARE_ENCRYPTION_BIT_P2: u32 = 52;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [503495679943923, 3594134491487581];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [2251799813881856, 2251799814176768];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_R1_LOW_BOUNDS: [Field; L] = [125873921148148, 898533630999902];
pub global SHARE_ENCRYPTION_R1_UP_BOUNDS: [Field; L] = [125873921148148, 898533630999902];
pub global SHARE_ENCRYPTION_R2_BOUNDS: [Field; L] = [2251799813881856, 2251799814176768];
pub global SHARE_ENCRYPTION_P1_BOUNDS: [Field; L] = [8192, 8192];
pub global SHARE_ENCRYPTION_P2_BOUNDS: [Field; L] = [2251799813881856, 2251799814176768];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 1125899917262848;

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

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 51;
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
