// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { BfvProtocol } from "./BfvProtocol.sol";

/// @notice Public-input layout of `dkg_aggregator_v2`, for honest-party count `h` and `rows` l-BFV
///         rows: nodes-fold key hash (1), party IDs (h), committee-hash limbs (2), legacy VK
///         binding (15), returned legacy key hash, C2a and C2b chunk key hashes (3), SK and ESM
///         aggregate commitments (2h), key-envelope commitment, V2 key hash, session limbs (2),
///         aggregator ID, accepted-set limbs (2), aggregate pk/d0/d2 (3 * rows) and the V2 VK
///         binding (11). `scripts/utils.ts` `bfvPkV2PublicInputLayout` mirrors it.
library BfvPkV2Layout {
    uint256 internal constant FIXED_LEN = 39;
    uint256 internal constant LEGACY_VK_BINDING_LEN = 15;
    uint256 internal constant V2_VK_BINDING_LEN = 11;
    /// @dev Index of the first party ID.
    uint256 internal constant PARTY_ID_START = 1;
    /// @dev Offset of the SK aggregate commitments after the `h` party IDs.
    uint256 internal constant COMMITMENT_OFFSET = 21;
    /// @dev l-BFV rows of the widest parameter set, secure-16384 (one per CRT modulus).
    uint256 internal constant MAX_ROWS = 6;

    function isLbfvParamSet(uint8 paramSet) internal pure returns (bool) {
        return
            paramSet == BfvProtocol.SECURE_16384_PARAM_SET ||
            paramSet == BfvProtocol.INSECURE_LBFV_PARAM_SET;
    }

    /// @dev secure-16384 compiles six rows, insecure l-BFV three.
    function rowCount(uint8 paramSet) internal pure returns (uint256) {
        return paramSet == BfvProtocol.SECURE_16384_PARAM_SET ? MAX_ROWS : 3;
    }

    function publicInputsLength(
        uint256 h,
        uint256 rows
    ) internal pure returns (uint256) {
        return FIXED_LEN + (3 * h) + (3 * rows);
    }

    function committeeHashHiIdx(uint256 h) internal pure returns (uint256) {
        return PARTY_ID_START + h;
    }

    function committeeHashLoIdx(uint256 h) internal pure returns (uint256) {
        return PARTY_ID_START + h + 1;
    }

    function legacyVkBindingStart(uint256 h) internal pure returns (uint256) {
        return 3 + h;
    }

    function skC2ChunkKeyHashIdx(uint256 h) internal pure returns (uint256) {
        return 19 + h;
    }

    function esmC2ChunkKeyHashIdx(uint256 h) internal pure returns (uint256) {
        return 20 + h;
    }

    function pkCommitmentIdx(uint256 h) internal pure returns (uint256) {
        return COMMITMENT_OFFSET + (3 * h);
    }

    function sessionHiIdx(uint256 h) internal pure returns (uint256) {
        return 23 + (3 * h);
    }

    function sessionLoIdx(uint256 h) internal pure returns (uint256) {
        return 24 + (3 * h);
    }

    function aggregatorIdIdx(uint256 h) internal pure returns (uint256) {
        return 25 + (3 * h);
    }

    function acceptedSetHiIdx(uint256 h) internal pure returns (uint256) {
        return 26 + (3 * h);
    }

    function acceptedSetLoIdx(uint256 h) internal pure returns (uint256) {
        return 27 + (3 * h);
    }

    function v2VkBindingStart(
        uint256 h,
        uint256 rows
    ) internal pure returns (uint256) {
        return 28 + (3 * h) + (3 * rows);
    }
}
