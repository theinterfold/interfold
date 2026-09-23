// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { InterfoldTicketToken } from "../token/InterfoldTicketToken.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { BondingRegistry } from "../registry/BondingRegistry.sol";
import { ExitQueueLib } from "./ExitQueueLib.sol";
import {
    BondOwnerHistoryStorage
} from "../storage/BondOwnerHistoryStorage.sol";
import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/**
 * @title BondingOwnershipLib
 * @notice Bond-owner assignment for `BondingRegistry`.
 *
 * @dev External, so this code is delegatecalled and does not count against the registry's
 * EIP-170 limit.
 *
 * The registry checks transfer authorization and locked balances before this library changes
 * ownership. The registry then checkpoints both owners' bonded balances.
 */
library BondingOwnershipLib {
    using ExitQueueLib for ExitQueueLib.ExitQueueState;
    using Checkpoints for Checkpoints.Trace208;

    // keccak256(abi.encode(uint256(keccak256(namespace)) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant OWNER_HISTORY_SLOT =
        0xfe211ffeb4589816a55506d3b74a3970b9121045b3d5fc44a9615b3f32a58e00;

    /// @notice Records ownership before either assignment path changes the current mapping.
    function _recordOwner(
        address operator,
        address previousOwner,
        address newOwner
    ) private {
        Checkpoints.Trace208 storage history = _ownerHistory().history[
            operator
        ];
        // Seed an existing operator lazily. No owner change after the upgrade can erase
        // the owner that a new request saw before that change.
        if (history.length() == 0)
            history.push(0, uint208(uint160(previousOwner)));
        history.push(
            SafeCast.toUint48(block.timestamp),
            uint208(uint160(newOwner))
        );
    }

    /// @notice Commits a transfer after the registry checks authorization and locked balances.
    function completeTransfer(
        mapping(address => address) storage bondOwners,
        mapping(address => address) storage pendingBondOwners,
        mapping(address => uint256) storage bondedByOwner,
        address operator,
        uint256 delegatedBond
    ) external {
        address previousOwner = bondOwners[operator];
        delete pendingBondOwners[operator];
        _recordOwner(operator, previousOwner, msg.sender);
        bondOwners[operator] = msg.sender;
        bondedByOwner[previousOwner] -= delegatedBond;
        bondedByOwner[msg.sender] += delegatedBond;
    }

    /// @notice Proposes a replacement owner without changing snapshot ownership.
    function proposeTransfer(
        mapping(address => address) storage bondOwners,
        mapping(address => address) storage pendingBondOwners,
        address operator,
        address newOwner
    ) external {
        if (msg.sender != bondOwners[operator]) {
            revert IBondingRegistry.NotBondOwner(msg.sender, operator);
        }
        require(newOwner != address(0), IBondingRegistry.ZeroAddress());
        pendingBondOwners[operator] = newOwner;
        emit IBondingRegistry.BondOwnerTransferProposed(
            operator,
            msg.sender,
            newOwner
        );
    }

    /// @notice Reads timestamp-based ownership, including unchanged pre-upgrade operators.
    function bondOwnerAt(
        mapping(address => address) storage bondOwners,
        address operator,
        uint256 timepoint
    ) external view returns (address) {
        Checkpoints.Trace208 storage history = _ownerHistory().history[
            operator
        ];
        if (history.length() == 0) return bondOwners[operator];
        return
            address(
                uint160(history.upperLookupRecent(SafeCast.toUint48(timepoint)))
            );
    }

    function _ownerHistory()
        private
        pure
        returns (BondOwnerHistoryStorage.OwnerHistoryLayout storage state)
    {
        bytes32 slot = OWNER_HISTORY_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            state.slot := slot
        }
    }

    /**
     * @notice Assign the caller's bond owner.
     * @dev Reassignment is refused once the operator holds anything, because the bond owner is
     * who collateral returns to. The check covers active bond, tickets, and amounts still queued
     * for exit — an operator mid-exit still has assets to return.
     * @param bondOwners Operator to bond-owner mapping.
     * @param pendingBondOwners Proposed owners in the two-step transfer flow.
     * @param operators The registry's operator records.
     * @param exits The registry's exit queue.
     * @param ticketToken The ticket token to read balances from.
     * @param bondOwner The owner being assigned.
     */
    function setBondOwner(
        mapping(address operator => address bondOwner) storage bondOwners,
        mapping(address operator => address pendingOwner)
            storage pendingBondOwners,
        mapping(address operator => BondingRegistry.Operator data)
            storage operators,
        ExitQueueLib.ExitQueueState storage exits,
        InterfoldTicketToken ticketToken,
        address bondOwner
    ) external {
        require(bondOwner != address(0), IBondingRegistry.ZeroAddress());

        address currentOwner = bondOwners[msg.sender];
        if (currentOwner != address(0)) {
            (uint256 pendingTicket, uint256 pendingCiphernodeBond) = exits
                .getPendingAmounts(msg.sender);
            BondingRegistry.Operator storage op = operators[msg.sender];
            if (
                op.registered ||
                op.ciphernodeBond != 0 ||
                pendingCiphernodeBond != 0 ||
                ticketToken.balanceOf(msg.sender) != 0 ||
                pendingTicket != 0
            ) {
                revert IBondingRegistry.BondOwnerAlreadySet(
                    msg.sender,
                    currentOwner
                );
            }
        }

        delete pendingBondOwners[msg.sender];
        _recordOwner(msg.sender, currentOwner, bondOwner);
        bondOwners[msg.sender] = bondOwner;

        emit IBondingRegistry.BondOwnerSet(msg.sender, bondOwner);
    }
}
