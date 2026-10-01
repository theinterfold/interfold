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
pub global QIS: [Field; L] = [576460752303439873, 576460752303702017];
pub global PLAINTEXT_MODULUS: Field = 144115188098531329;
pub global Q_MOD_T: Field = 8200076927336457;
pub global Q_MOD_T_CENTERED: Field = 8200076927336457;

// Parity matrix is sized for the active committee and the secure-8192 threshold QIS;
// see `committee/{name}/parity_secure.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters

pub global PK_BIT_PK: u32 = 59;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

// share_computation_sk - bit parameters
pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 58;
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
pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 57;

// verify_shares - configs
pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 59;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 59;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 58;
pub global SHARE_ENCRYPTION_CT0_BIT_R: u32 = 55;
pub global SHARE_ENCRYPTION_CT1_BIT_R: u32 = 13;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [240095369310641205, 34620936476510664];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [288230376151719936, 288230376151851008];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_CT0_R_BOUNDS: [Field; L] = [30011921168555547, 4327617060246757];
pub global SHARE_ENCRYPTION_CT1_R_BOUNDS: [Field; L] = [4096, 4096];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 144115188098531329;

// Scaled-quotient form of the `k0 * k1` term. `SCALED_QUOTIENT` is false for parameter sets that
// cannot use it (notably L = 1, where `DELTA < q`); the circuit then keeps the direct `k1` path and
// the constants below go unused.
pub global SHARE_ENCRYPTION_SCALED_QUOTIENT: bool = true;
pub global SHARE_ENCRYPTION_SCALE_K: Field = 4;
pub global SHARE_ENCRYPTION_DELTA: Field = 2305843008852066296;
pub global SHARE_ENCRYPTION_SMALL_D: [Field; L] = [361693196, 362741772];
pub global SHARE_ENCRYPTION_ALPHA: [Field; L] = [3415324443819497, 492478180464660];
pub global SHARE_ENCRYPTION_BETA: [Field; L] = [60023842337102902, 8655234120485321];
pub global SHARE_ENCRYPTION_BIT_Z: u32 = 53;
pub global SHARE_ENCRYPTION_T_POW_BIT: u32 = 57;
pub global SHARE_ENCRYPTION_T_GAP: Field = 22675457;
pub global SHARE_ENCRYPTION_T_GAP_BIT: u32 = 25;
pub global SHARE_ENCRYPTION_BIT_Q0: u32 = 27;
pub global SHARE_ENCRYPTION_Q0_OFFSET: Field = 4097;
pub global SHARE_ENCRYPTION_BIT_Q0_DIFF: u32 = 19;
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
);

/************************************
-------------------------------------
share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)
share_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)
-------------------------------------
************************************/

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 58;
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
