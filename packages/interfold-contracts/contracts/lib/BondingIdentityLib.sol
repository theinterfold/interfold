// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IBondingIdentity } from "../interfaces/IBondingIdentity.sol";
import { IBondOwnerHistory } from "../interfaces/IBondOwnerHistory.sol";
import {
    IOwnerIdentityRegistry
} from "../interfaces/IOwnerIdentityRegistry.sol";
import { BondingIdentityStorage } from "../storage/BondingIdentityStorage.sol";
import { BondOwnerCapacityLib } from "./BondOwnerCapacityLib.sol";

/// @notice Applies an independent identity policy to historical bond owners.
library BondingIdentityLib {
    using Checkpoints for Checkpoints.Trace208;

    function layout()
        internal
        pure
        returns (BondingIdentityStorage.IdentityLayout storage state)
    {
        // ERC-7201: interfold.storage.BondingIdentity
        bytes32 slot = keccak256(
            abi.encode(
                uint256(keccak256("interfold.storage.BondingIdentity")) - 1
            )
        ) & ~bytes32(uint256(0xff));
        // solhint-disable-next-line no-inline-assembly
        assembly {
            state.slot := slot
        }
    }

    function policyAt(
        uint256 timepoint
    ) internal view returns (IBondingIdentity.IdentityPolicy memory) {
        BondingIdentityStorage.IdentityLayout storage state = layout();
        return
            state.policies[
                state.policyVersions.upperLookupRecent(
                    SafeCast.toUint48(timepoint)
                )
            ];
    }

    function setPolicy(address registry, bool required) internal {
        if (required) {
            if (registry.code.length == 0)
                revert IBondingIdentity.InvalidIdentityRegistry(registry);
            IOwnerIdentityRegistry(registry).isVerifiedAt(
                address(0),
                block.timestamp
            );
        }
        BondingIdentityStorage.IdentityLayout storage state = layout();
        uint208 version = state.policyVersions.latest();
        IBondingIdentity.IdentityPolicy memory policy = state.policies[version];
        if (policy.registry == registry && policy.required == required) return;
        state.policies[version + 1] = IBondingIdentity.IdentityPolicy(
            registry,
            required
        );
        uint48 timepoint = SafeCast.toUint48(block.timestamp);
        state.policyVersions.push(timepoint, version + 1);
        BondOwnerCapacityLib.reset();
        emit IBondingIdentity.IdentityPolicyUpdated(
            timepoint,
            registry,
            required
        );
    }

    function allows(
        address operator,
        uint256 timepoint
    ) internal view returns (bool) {
        IBondingIdentity.IdentityPolicy memory policy = policyAt(timepoint);
        if (!policy.required) return true;
        address bondOwner = IBondOwnerHistory(address(this)).bondOwnerAt(
            operator,
            timepoint
        );
        return
            IOwnerIdentityRegistry(policy.registry).isVerifiedAt(
                bondOwner,
                timepoint
            );
    }

    function capacityPolicyMatches(
        uint256 timepoint
    ) internal view returns (bool) {
        Checkpoints.Trace208 storage versions = layout().policyVersions;
        return
            versions.upperLookupRecent(SafeCast.toUint48(timepoint)) ==
            versions.latest();
    }
}
