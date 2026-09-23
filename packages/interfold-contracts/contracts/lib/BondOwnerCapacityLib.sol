// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    BondOwnerHistoryStorage
} from "../storage/BondOwnerHistoryStorage.sol";
import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Maintains a conservative count of active bond owners for request admission.
library BondOwnerCapacityLib {
    using Checkpoints for Checkpoints.Trace208;

    // ERC-7201: interfold.storage.BondOwnerHistory
    bytes32 private constant STORAGE_SLOT =
        0xfe211ffeb4589816a55506d3b74a3970b9121045b3d5fc44a9615b3f32a58e00;

    function layout()
        internal
        pure
        returns (BondOwnerHistoryStorage.OwnerHistoryLayout storage state)
    {
        bytes32 slot = STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            state.slot := slot
        }
    }

    function reset() internal {
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state = layout();
        ++state.capacityVersion;
        state.activeOwnerCounts.push(SafeCast.toUint48(block.timestamp), 0);
    }

    /// @dev An unchanged legacy operator enters the count on its first status refresh.
    function sync(address operator, address owner, bool active) internal {
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state = layout();
        if (state.capacityVersion == 0) reset();
        BondOwnerHistoryStorage.CountedOperator storage counted = state
            .countedOperators[operator];
        address previous = counted.version == state.capacityVersion
            ? counted.owner
            : address(0);
        address next = active ? owner : address(0);
        if (previous == next) return;
        _move(state, previous, next);
        counted.version = state.capacityVersion;
        counted.owner = next;
    }

    /// @dev Transfers cannot enroll unrefreshed or inactive operators into the count.
    function transfer(address operator, address owner) internal {
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state = layout();
        BondOwnerHistoryStorage.CountedOperator storage counted = state
            .countedOperators[operator];
        if (
            counted.version != state.capacityVersion ||
            counted.owner == address(0)
        ) return;
        _move(state, counted.owner, owner);
        counted.owner = owner;
    }

    function _move(
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state,
        address previous,
        address next
    ) private {
        if (previous == next) return;
        uint256 total = state.activeOwnerCounts.latest();
        uint256 updated = total;
        if (
            previous != address(0) &&
            --state.activeOperators[state.capacityVersion][previous] == 0
        ) --updated;
        if (
            next != address(0) &&
            state.activeOperators[state.capacityVersion][next]++ == 0
        ) ++updated;
        if (updated != total)
            state.activeOwnerCounts.push(
                SafeCast.toUint48(block.timestamp),
                SafeCast.toUint208(updated)
            );
    }

    function countAt(uint256 timepoint) internal view returns (uint256) {
        return
            layout().activeOwnerCounts.upperLookupRecent(
                SafeCast.toUint48(timepoint)
            );
    }
}
