// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    BondOwnerHistoryStorage
} from "../storage/BondOwnerHistoryStorage.sol";
import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IBondingIdentity } from "../interfaces/IBondingIdentity.sol";
import {
    IOwnerIdentityRegistry
} from "../interfaces/IOwnerIdentityRegistry.sol";
import { BondingIdentityLib } from "./BondingIdentityLib.sol";

/// @notice Maintains a conservative count of active bond owners for request admission.
library BondOwnerCapacityLib {
    /// @dev Under a required identity policy, owner capacity covers fixed windows. An owner counts
    ///      only when its credential lasts to the end of the current window, so no credential can
    ///      make the count stale before the window ends.
    uint256 internal constant IDENTITY_CAPACITY_WINDOW = 30 days;

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
        uint48 timepoint = SafeCast.toUint48(block.timestamp);
        state.activeOwnerCounts.push(timepoint, 0);
        // Read storage, not address(this): the initializer runs inside the proxy constructor,
        // where the proxy has no code yet.
        IBondingIdentity.IdentityPolicy memory policy = BondingIdentityLib
            .policyAt(timepoint);
        // Without a required policy, no credential bounds the count.
        state.capacityIdentityExpiries.push(
            timepoint,
            policy.required ? _windowEnd(timepoint) : type(uint48).max
        );
        state.capacityRevocationCounts.push(
            timepoint,
            policy.required
                ? SafeCast.toUint208(
                    IOwnerIdentityRegistry(policy.registry).revocationCountAt(
                        timepoint
                    )
                )
                : 0
        );
    }

    /// @dev An unchanged legacy operator enters the count on its first status refresh.
    function sync(address operator, address owner, bool active) internal {
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state = layout();
        IBondingIdentity.IdentityPolicy
            memory policy = _prepareIdentityCapacity();
        BondOwnerHistoryStorage.CountedOperator storage counted = state
            .countedOperators[operator];
        address previous = counted.version == state.capacityVersion
            ? counted.owner
            : address(0);
        address next = active && _coversWindow(policy, owner)
            ? owner
            : address(0);
        if (previous == next) return;
        _move(state, previous, next);
        counted.version = state.capacityVersion;
        counted.owner = next;
    }

    /// @dev Transfers cannot enroll unrefreshed or inactive operators into the count.
    function transfer(address operator, address owner) internal {
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state = layout();
        IBondingIdentity.IdentityPolicy
            memory policy = _prepareIdentityCapacity();
        BondOwnerHistoryStorage.CountedOperator storage counted = state
            .countedOperators[operator];
        if (
            counted.version != state.capacityVersion ||
            counted.owner == address(0)
        ) return;
        address next = _coversWindow(policy, owner) ? owner : address(0);
        _move(state, counted.owner, next);
        counted.owner = next;
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
        IBondingIdentity.IdentityPolicy memory policy = BondingIdentityLib
            .policyAt(timepoint);
        if (!_identityCapacityIsFresh(policy, timepoint)) return 0;
        return
            layout().activeOwnerCounts.upperLookupRecent(
                SafeCast.toUint48(timepoint)
            );
    }

    function _prepareIdentityCapacity()
        private
        returns (IBondingIdentity.IdentityPolicy memory policy)
    {
        policy = BondingIdentityLib.policyAt(block.timestamp);
        if (
            layout().capacityVersion == 0 ||
            !_identityCapacityIsFresh(policy, block.timestamp)
        ) reset();
    }

    function _identityCapacityIsFresh(
        IBondingIdentity.IdentityPolicy memory policy,
        uint256 timepoint
    ) private view returns (bool) {
        if (!policy.required) return true;
        BondOwnerHistoryStorage.OwnerHistoryLayout storage state = layout();
        uint48 key = SafeCast.toUint48(timepoint);
        return
            timepoint <=
            state.capacityIdentityExpiries.upperLookupRecent(key) &&
            IOwnerIdentityRegistry(policy.registry).revocationCountAt(
                timepoint
            ) ==
            state.capacityRevocationCounts.upperLookupRecent(key);
    }

    function _coversWindow(
        IBondingIdentity.IdentityPolicy memory policy,
        address owner
    ) private view returns (bool) {
        if (!policy.required) return true;
        (, uint48 expiresAt) = IOwnerIdentityRegistry(policy.registry)
            .identityOf(owner);
        return expiresAt >= layout().capacityIdentityExpiries.latest();
    }

    /// @dev The last second of the capacity window that contains `timepoint`.
    function _windowEnd(uint48 timepoint) private pure returns (uint48) {
        return
            SafeCast.toUint48(
                (timepoint / IDENTITY_CAPACITY_WINDOW + 1) *
                    IDENTITY_CAPACITY_WINDOW -
                    1
            );
    }
}
