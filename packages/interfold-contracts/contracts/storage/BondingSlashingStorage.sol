// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import {
    EnumerableSet
} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

struct SlashingManagerObligations {
    uint256 e3Assignments;
    uint256 openSlashLocks;
    uint256 activeBans;
}

struct BondingSlashLock {
    uint256 e3Id;
    address operator;
}

// keccak256(abi.encode(uint256(keccak256("interfold.storage.BondingSlashing")) - 1)) & ~bytes32(uint256(0xff))
bytes32 constant BONDING_SLASHING_STORAGE_SLOT = 0x1681355f1bd0922b89c3b8bc6b781718ce17614b616c8d2f8b40c2ed56012900;

/// @notice Declares the namespaced manager state used by BondingRegistry.
abstract contract BondingSlashingStorage {
    /// @custom:storage-location erc7201:interfold.storage.BondingSlashing
    struct Layout {
        mapping(address operator => uint256 count) openSlashLocks;
        mapping(address operator => uint256 count) activeBans;
        mapping(address manager => SlashingManagerObligations obligations) managers;
        mapping(address manager => mapping(uint256 proposalId => BondingSlashLock lock)) slashLocks;
        mapping(address manager => mapping(address operator => bool banned)) managerBans;
        mapping(address manager => mapping(uint256 e3Id => uint256 count)) e3Locks;
        mapping(address manager => mapping(uint256 e3Id => uint256 count)) e3Routes;
        mapping(address manager => mapping(uint256 e3Id => address interfold)) e3Interfold;
        mapping(uint256 e3Id => address registry) committeeRegistries;
        mapping(uint256 e3Id => mapping(address operator => bool locked)) committeeObligations;
        mapping(uint256 e3Id => uint256 count) committeeMemberCounts;
        mapping(address operator => uint256 count) unresolvedCommittees;
        uint256 unresolvedCommitteeCount;
        /// @dev E3s whose committee holds collateral, for the obligation views. It omits the
        ///      committees that were requested before this member existed, so its length is at
        ///      most `unresolvedCommitteeCount`.
        EnumerableSet.UintSet unresolvedCommitteeIds;
    }
}
