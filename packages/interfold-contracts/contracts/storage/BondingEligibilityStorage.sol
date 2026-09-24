// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

/// @notice Declares the namespaced eligibility history used by BondingRegistry.
abstract contract BondingEligibilityStorage {
    /// @custom:storage-location erc7201:interfold.storage.BondingEligibility
    struct EligibilityLayout {
        mapping(address operator => Checkpoints.Trace208 activeVersion) operatorActiveVersions;
        Checkpoints.Trace208 configurationVersions;
        Checkpoints.Trace208 activeOperatorCounts;
        uint256 refreshEpoch;
        uint256 pendingRefreshes;
        uint48 refreshCompletedAt;
        mapping(address operator => uint256 epoch) refreshedEpochs;
    }
}
