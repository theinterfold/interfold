// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use crate::configs::secure::threshold::{
    L as L_THRESHOLD, QIS as QIS_THRESHOLD,
    THRESHOLD_SHARE_DECRYPTION_BIT_SK as SHARE_DECRYPTION_BIT_AGG,
};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for DKG secure preset
pub global N: u32 = 8192;
pub global L: u32 = 2;
pub global QIS: [Field; L] = [1152921504606994433, 1152921504607191041];
pub global PLAINTEXT_MODULUS: Field = 288230376164294657;
pub global Q_MOD_T: Field = 2508586813587465;
pub global Q_MOD_T_CENTERED: Field = 2508586813587465;

// Parity matrix is sized for the active committee and the secure-8192 threshold QIS;
// see `committee/{name}/parity_secure.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE as PARITY_MATRIX;

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

// share_computation_sk - bit parameters
pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 59;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;

// share_computation_sk - configs
pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

// share_computation_e_sm - bit parameters
pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 147;

// verify_shares - configs
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
pub global SHARE_ENCRYPTION_BIT_R1: u32 = 58;
pub global SHARE_ENCRYPTION_BIT_R2: u32 = 60;
pub global SHARE_ENCRYPTION_BIT_P1: u32 = 13;
pub global SHARE_ENCRYPTION_BIT_P2: u32 = 60;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [362086980741092512, 639891851793844136];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [576460752303497216, 576460752303595520];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_R1_LOW_BOUNDS: [Field; L] = [90521745189217441, 159972962955401129];
pub global SHARE_ENCRYPTION_R1_UP_BOUNDS: [Field; L] = [4096, 4096];
pub global SHARE_ENCRYPTION_R2_BOUNDS: [Field; L] = [576460752303497216, 576460752303595520];
pub global SHARE_ENCRYPTION_P1_BOUNDS: [Field; L] = [4096, 4096];
pub global SHARE_ENCRYPTION_P2_BOUNDS: [Field; L] = [576460752303497216, 576460752303595520];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 288230376164294656;

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
