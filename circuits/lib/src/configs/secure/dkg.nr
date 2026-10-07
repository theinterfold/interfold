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
pub global QIS: [Field; L] = [2305843009214758913, 2305843009214988289];
pub global PLAINTEXT_MODULUS: Field = 576460752317792257;
pub global Q_MOD_T: Field = 3169161947774985;
pub global Q_MOD_T_CENTERED: Field = 3169161947774985;

// Parity matrix is sized for the active committee and the secure-8192 threshold QIS;
// see `committee/{name}/parity_secure.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_SECURE as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters

pub global PK_BIT_PK: u32 = 61;

/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

// share_computation_sk - bit parameters
pub global SHARE_COMPUTATION_BIT_SHARE: u32 = 60;
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
pub global SHARE_COMPUTATION_E_SM_BIT_SECRET: u32 = 59;

// verify_shares - configs
pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global SHARE_ENCRYPTION_BIT_PK: u32 = 61;
pub global SHARE_ENCRYPTION_BIT_CT: u32 = 61;
pub global SHARE_ENCRYPTION_BIT_U: u32 = 1;
pub global SHARE_ENCRYPTION_BIT_E0: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_E1: u32 = 5;
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = 60;
pub global SHARE_ENCRYPTION_CT0_BIT_R: u32 = 59;
pub global SHARE_ENCRYPTION_CT1_BIT_R: u32 = 13;

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [493937176208329543, 1434253984466648362];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [1152921504607379456, 1152921504607494144];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_E1_BOUND: Field = 20;
pub global SHARE_ENCRYPTION_U_BOUND: Field = 1;
pub global SHARE_ENCRYPTION_CT0_R_BOUNDS: [Field; L] = [123484294055107400, 358563496125402411];
pub global SHARE_ENCRYPTION_CT1_R_BOUNDS: [Field; L] = [4096, 4096];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = 576460752317792257;

// Scaled-quotient form of the `k0 * k1` term. `SCALED_QUOTIENT` is false for parameter sets that
// cannot use it (notably L = 1, where `DELTA < q`); the circuit then keeps the direct `k1` path and
// the constants below go unused.
pub global SHARE_ENCRYPTION_SCALED_QUOTIENT: bool = true;
pub global SHARE_ENCRYPTION_SCALE_K: Field = 4;
pub global SHARE_ENCRYPTION_DELTA: Field = 9223372036634312696;
pub global SHARE_ENCRYPTION_SMALL_D: [Field; L] = [224722956, 225640460];
pub global SHARE_ENCRYPTION_ALPHA: [Field; L] = [678869678974347, 1971245714843270];
pub global SHARE_ENCRYPTION_BETA: [Field; L] = [123484294055103304, 358563496125398315];
pub global SHARE_ENCRYPTION_BIT_Z: u32 = 52;
pub global SHARE_ENCRYPTION_T_POW_BIT: u32 = 59;
pub global SHARE_ENCRYPTION_T_GAP: Field = 14368769;
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

pub global SHARE_DECRYPTION_BIT_MSG: u32 = 60;
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
