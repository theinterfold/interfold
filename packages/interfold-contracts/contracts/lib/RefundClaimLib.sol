// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity >=0.8.27;

import { IE3RefundManager } from "../interfaces/IE3RefundManager.sol";

/// @title RefundClaimLib
/// @notice Eligibility checks for an honest-node reward claim, folded out of
///         `E3RefundManager` for contract size. One call replaces five inline
///         reverts and a roster walk. Revert precedence is unchanged: the
///         checks run in the order the inline code ran them.
library RefundClaimLib {
    /// @notice Validate a claim and return what it may take.
    /// @return baseClaimable True when the base per-node reward is still owed.
    /// @return topUp Held top-up owed to the operator, zero when none.
    function validateHonestNodeClaim(
        uint256 e3Id,
        address operator,
        address[] storage honestNodes,
        mapping(address => bool) storage claimed,
        mapping(address => address) storage recipients,
        uint256 pendingExpulsions,
        uint256 heldTopUp,
        bool excluded
    )
        external
        view
        returns (bool baseClaimable, uint256 topUp, address recipient)
    {
        uint256 len = honestNodes.length;
        bool isHonest = false;
        for (uint256 i = 0; i < len && !isHonest; i++) {
            isHonest = (honestNodes[i] == operator);
        }
        if (!isHonest) revert IE3RefundManager.NotHonestNode(e3Id, operator);

        if (pendingExpulsions != 0) {
            revert IE3RefundManager.RewardPendingExpulsion(e3Id, operator);
        }
        baseClaimable = !claimed[operator] && !excluded;
        topUp = heldTopUp;
        if (!baseClaimable && topUp == 0) {
            revert IE3RefundManager.AlreadyClaimed(e3Id, operator);
        }

        recipient = recipients[operator];
        if (recipient == address(0)) {
            revert IE3RefundManager.RewardRecipientNotSnapshotted(
                e3Id,
                operator
            );
        }
        if (msg.sender != recipient) revert IE3RefundManager.Unauthorized();
    }
}
