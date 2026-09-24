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
import { BondingAdmissionLib } from "./BondingAdmissionLib.sol";
import { BondingEligibilityLib } from "./BondingEligibilityLib.sol";

/**
 * @title BondingRegistrationLib
 * @notice Operator registration and deregistration for `BondingRegistry`.
 *
 * @dev External, so this code is delegatecalled and does not count against the registry's
 * EIP-170 limit. The registry sits within a few hundred bytes of that limit, which is why it
 * already keeps most of its logic in sibling libraries.
 *
 * The `Operator` struct is referenced from `BondingRegistry` rather than moved here. Its storage
 * layout is recorded in the upgrade baseline as `struct BondingRegistry.Operator`, and the
 * baseline compares type *labels* — relocating the declaration would read as a type change on a
 * layout that did not actually change.
 */
library BondingRegistrationLib {
    using ExitQueueLib for ExitQueueLib.ExitQueueState;

    /// @dev Must match the constants of the same name in `BondingRegistry`, which are private.
    /// Both are string literals, so they are compared by eye rather than by the compiler.
    bytes32 private constant REASON_WITHDRAW = bytes32("WITHDRAW");
    bytes32 private constant REASON_UNBOND = bytes32("UNBOND");

    /**
     * @notice Validate a registration and mark the operator registered.
     * @dev Stops short of `numRegisteredOperators` and `addCiphernode`, which stay on the
     * registry. The counter is a scalar and cannot be passed by reference, and the original
     * increments it *before* calling into the ciphernode registry — so leaving both there keeps
     * that order, rather than opening a window where the operator reads as registered but
     * uncounted.
     * @param operators The registry's operator records.
     * @param operator The operator being registered.
     * @param slashingManager The configured slashing manager, which must be set.
     * @param requiredCiphernodeBond The bond an operator must hold to register.
     * @param banned Whether the operator is currently banned. Evaluated by the registry so this
     * library need not be linked against `BondingSlashingLib` in every deployment path;
     * `activeBanCount` is a view that cannot revert, so computing it earlier does not change
     * which require fires first when more than one would fail.
     */
    function register(
        mapping(address operator => BondingRegistry.Operator data)
            storage operators,
        address operator,
        address slashingManager,
        uint256 requiredCiphernodeBond,
        bool banned
    ) external {
        // Clear previous exit request
        if (operators[operator].exitRequested) {
            operators[operator].exitRequested = false;
            operators[operator].exitUnlocksAt = 0;
        }

        // Order preserved from the original: the slashing-manager check precedes the ban check,
        // and revert precedence is observable.
        require(slashingManager != address(0), IBondingRegistry.ZeroAddress());
        require(!banned, IBondingRegistry.CiphernodeBanned());
        require(
            !operators[operator].registered,
            IBondingRegistry.AlreadyRegistered()
        );
        require(
            operators[operator].ciphernodeBond >= requiredCiphernodeBond,
            IBondingRegistry.NotCiphernodeBonded()
        );

        BondingEligibilityLib.excludeNewRegistration(operator);
        operators[operator].registered = true;
        BondingAdmissionLib.start(operator);
    }

    /**
     * @notice Mark an operator deregistered and open its exit window.
     * @dev Split from {releaseAssets} so the registry can decrement `numRegisteredOperators`
     * between the two, which is where the original decrements it — before any token call.
     * @param operators The registry's operator records.
     * @param operator The operator being deregistered.
     * @param exitDelay Seconds before the exit unlocks.
     * @return exitUnlocksAt When the exit unlocks.
     */
    function markDeregistered(
        mapping(address operator => BondingRegistry.Operator data)
            storage operators,
        address operator,
        uint64 exitDelay
    ) external returns (uint64 exitUnlocksAt) {
        BondingRegistry.Operator storage op = operators[operator];
        require(op.registered, IBondingRegistry.NotRegistered());

        BondingEligibilityLib.completeOperatorRefresh(operator);
        op.registered = false;
        op.exitRequested = true;
        op.exitUnlocksAt = uint64(block.timestamp) + exitDelay;

        return op.exitUnlocksAt;
    }

    /**
     * @notice Burn an operator's tickets, zero its bond, and queue both for exit.
     * @dev Emitted from the library, so the events still come from the registry's address under
     * delegatecall.
     * @param operators The registry's operator records.
     * @param exits The registry's exit queue.
     * @param ticketToken The ticket token to burn from.
     * @param operator The operator being deregistered.
     * @param exitDelay Seconds before the exit unlocks.
     */
    function releaseAssets(
        mapping(address operator => BondingRegistry.Operator data)
            storage operators,
        ExitQueueLib.ExitQueueState storage exits,
        InterfoldTicketToken ticketToken,
        address operator,
        uint64 exitDelay
    ) external {
        BondingRegistry.Operator storage op = operators[operator];

        uint256 ticketOut = ticketToken.balanceOf(operator);
        uint256 ciphernodeBondOut = op.ciphernodeBond;
        if (ticketOut != 0) {
            ticketToken.burnTickets(operator, ticketOut);
            emit IBondingRegistry.TicketBalanceUpdated(
                operator,
                -int256(ticketOut),
                0,
                REASON_WITHDRAW
            );
        }
        if (ciphernodeBondOut != 0) {
            op.ciphernodeBond = 0;
            emit IBondingRegistry.CiphernodeBondUpdated(
                operator,
                -int256(ciphernodeBondOut),
                0,
                REASON_UNBOND
            );
        }

        if (ticketOut != 0 || ciphernodeBondOut != 0) {
            exits.queueAssetsForExit(
                operator,
                exitDelay,
                ticketOut,
                ciphernodeBondOut
            );
        }
    }
}
