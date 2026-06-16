// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use crate::configs::insecure::threshold::{
    L as L_THRESHOLD, QIS as QIS_THRESHOLD,
    THRESHOLD_SHARE_DECRYPTION_BIT_SK as SHARE_DECRYPTION_BIT_AGG,
};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for DKG insecure preset
pub global N: u32 = 512;
pub global L: u32 = 1;
pub global QIS: [Field; L] = [2251799813554177];
pub global PLAINTEXT_MODULUS: Field = 68719403009;
pub global Q_MOD_T: Field = 2415755265;
pub global Q_MOD_T_CENTERED: Field = 2415755265;

// Parity matrix is sized for the active committee and the insecure-512 threshold QIS;
// see `committee/{name}/parity_insecure.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_INSECURE as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters
pub global PK_BIT_PK: u32 = 50;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 36;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;

pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 28;

pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 50;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 50;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 3;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 3;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 36;
pub global SHARE_ENCRYPTION_BIT_R1: u32 = 35;
pub global SHARE_ENCRYPTION_BIT_R2: u32 = 50;
pub global SHARE_ENCRYPTION_BIT_P1: u32 = 9;
pub global SHARE_ENCRYPTION_BIT_P2: u32 = 50;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [1284838520228573];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [1125899906777088];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 6;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 6;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_R1_LOW_BOUNDS: [Field; L] = [19605059183];
pub global SHARE_ENCRYPTION_R1_UP_BOUNDS: [Field; L] = [19605059183];
pub global SHARE_ENCRYPTION_R2_BOUNDS: [Field; L] = [1125899906777088];
pub global SHARE_ENCRYPTION_P1_BOUNDS: [Field; L] = [256];
pub global SHARE_ENCRYPTION_P2_BOUNDS: [Field; L] = [1125899906777088];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 68719403008;

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

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 36;
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
