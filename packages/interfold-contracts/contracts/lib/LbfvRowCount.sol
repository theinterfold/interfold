// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { ActiveCryptoConfig } from "./ActiveCryptoConfig.sol";

/// @notice Single on-chain owner of the number of l-BFV CRT rows per BFV parameter set.
/// @dev Mirrors `lbfv_row_count` in `crates/fhe-params/src/lbfv.rs` (the preset's modulus
///      count). Every on-chain consumer of the row count (the pk verifier public-input
///      layout, the DKG fold statement length, slashing proof-instance bounds) MUST read it
///      from here. A new l-BFV parameter set is added in this one function.
library LbfvRowCount {
    /// @dev Insecure l-BFV presets (parameter sets 4 and 5).
    uint256 internal constant INSECURE_ROWS = 3;
    /// @dev secure-16384 and secure-16384-simd (parameter sets 3 and 6).
    uint256 internal constant SECURE_16384_ROWS = 5;
    /// @dev secure-16384-simd-d6 (parameter set 7).
    uint256 internal constant SECURE_16384_SIMD_D6_ROWS = 8;

    /// @notice Number of l-BFV rows compiled for `paramSet`.
    /// @dev secure-16384-simd-d6 compiles eight rows, secure-16384 and secure-16384-simd five,
    ///      and the insecure l-BFV presets three. Returns zero for parameter sets that do not
    ///      run the l-BFV path (the trBFV sets), which have no row-indexed proofs.
    function rowCount(uint8 paramSet) internal pure returns (uint256) {
        if (paramSet == ActiveCryptoConfig.SECURE_16384_SIMD_D6_PARAM_SET) {
            return SECURE_16384_SIMD_D6_ROWS;
        }
        if (
            paramSet == ActiveCryptoConfig.SECURE_16384_PARAM_SET ||
            paramSet == ActiveCryptoConfig.SECURE_16384_SIMD_PARAM_SET
        ) {
            return SECURE_16384_ROWS;
        }
        if (
            paramSet == ActiveCryptoConfig.INSECURE_LBFV_PARAM_SET ||
            paramSet == ActiveCryptoConfig.INSECURE_SIMD_PARAM_SET
        ) {
            return INSECURE_ROWS;
        }
        return 0;
    }

    /// @notice Whether some supported l-BFV parameter set compiles exactly `rows` rows.
    /// @dev Mirrors `is_supported_lbfv_row_count` in `crates/fhe-params/src/lbfv.rs`.
    function isSupportedRowCount(uint256 rows) internal pure returns (bool) {
        return
            rows == INSECURE_ROWS ||
            rows == SECURE_16384_ROWS ||
            rows == SECURE_16384_SIMD_D6_ROWS;
    }
}
