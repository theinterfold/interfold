// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

/// @notice Declares additive bond-owner history without changing the legacy storage layout.
abstract contract BondOwnerHistoryStorage {
    struct CountedOperator {
        uint256 version;
        address owner;
    }

    /// @custom:storage-location erc7201:interfold.storage.BondOwnerHistory
    struct OwnerHistoryLayout {
        mapping(address operator => Checkpoints.Trace208 owners) history;
        mapping(uint256 version => mapping(address owner => uint256 count)) activeOperators;
        mapping(address operator => CountedOperator counted) countedOperators;
        Checkpoints.Trace208 activeOwnerCounts;
        uint256 capacityVersion;
    }
}
