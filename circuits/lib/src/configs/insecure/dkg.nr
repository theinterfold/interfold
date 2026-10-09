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
pub global N: u32 = 64;
pub global L: u32 = 2;
pub global QIS: [Field; L] = [536852993, 536854657];
pub global PLAINTEXT_MODULUS: Field = 134217089;
pub global Q_MOD_T: Field = 76240648;
pub global Q_MOD_T_CENTERED: Field = -57976441;

// Parity matrix is sized for the active committee and the insecure-64 threshold QIS;
// see `committee/{name}/parity_insecure.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_INSECURE as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters
pub global PK_BIT_PK: u32 = 28;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 27;
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = 1;

pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 26;

pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 28;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 28;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 27;
pub global SHARE_ENCRYPTION_CT0_BIT_R: u32 = 26;
pub global SHARE_ENCRYPTION_CT1_BIT_R: u32 = 6;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [71356754, 202412899];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [268426496, 268427328];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_CT0_R_BOUNDS: [Field; L] = [17839731, 50604548];
pub global SHARE_ENCRYPTION_CT1_R_BOUNDS: [Field; L] = [32, 32];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 134217089;

// Scaled-quotient form of the `k0 * k1` term. `SCALED_QUOTIENT` is false for parameter sets that
// cannot use it (notably L = 1, where `DELTA < q`); the circuit then keeps the direct `k1` path and
// the constants below go unused.
pub global SHARE_ENCRYPTION_SCALED_QUOTIENT: bool = true;
pub global SHARE_ENCRYPTION_SCALE_K: Field = 4;
pub global SHARE_ENCRYPTION_DELTA: Field = 2147357177;
pub global SHARE_ENCRYPTION_SMALL_D: [Field; L] = [54795, 61451];
pub global SHARE_ENCRYPTION_ALPHA: [Field; L] = [10133659, 28745379];
pub global SHARE_ENCRYPTION_BETA: [Field; L] = [17839699, 50604516];
pub global SHARE_ENCRYPTION_BIT_Z: u32 = 27;
pub global SHARE_ENCRYPTION_T_POW_BIT: u32 = 26;
pub global SHARE_ENCRYPTION_T_GAP: Field = 67108225;
pub global SHARE_ENCRYPTION_T_GAP_BIT: u32 = 26;
pub global SHARE_ENCRYPTION_BIT_Q0: u32 = 14;
pub global SHARE_ENCRYPTION_Q0_OFFSET: Field = 33;
pub global SHARE_ENCRYPTION_BIT_Q0_DIFF: u32 = 11;
pub global SHARE_ENCRYPTION_Q0_DIFF_OFFSET: Field = 66;
pub global SHARE_ENCRYPTION_BIT_Q1: u32 = 7;
pub global SHARE_ENCRYPTION_Q1_OFFSET: Field = 33;

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

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 27;
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
