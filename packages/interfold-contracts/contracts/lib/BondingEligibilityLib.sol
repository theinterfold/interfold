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
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import {
    BondingEligibilityStorage
} from "../storage/BondingEligibilityStorage.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { INodeReleaseManager } from "../interfaces/INodeReleaseManager.sol";
import { INodeReleaseRegistry } from "../interfaces/INodeReleaseRegistry.sol";
import { InterfoldTicketToken } from "../token/InterfoldTicketToken.sol";
import { BondOwnerCapacityLib } from "./BondOwnerCapacityLib.sol";

/// @notice Stores the request-boundary eligibility history for BondingRegistry.
library BondingEligibilityLib {
    using Checkpoints for Checkpoints.Trace208;

    struct OperatorRequirements {
        bool registered;
        bool banned;
        uint256 ciphernodeBond;
        uint256 requiredCiphernodeBond;
        uint256 ciphernodeBondActiveBps;
        address registry;
        address ticketToken;
        uint256 ticketPrice;
        uint256 minTicketBalance;
    }

    // keccak256(abi.encode(uint256(keccak256("interfold.storage.BondingEligibility")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_SLOT =
        0x47c917bbb1b321238f7fc4a5d1afedaac975b8f7b2dd6ce265eb240352449e00;

    function invalidateConfiguration(
        uint256 configurationVersion
    ) external returns (uint256 newVersion) {
        return _invalidateConfiguration(configurationVersion);
    }

    function requireNodeReleaseRegistry(
        address registry,
        address caller
    ) external view {
        address interfold = address(ICiphernodeRegistry(registry).interfold());
        if (
            caller !=
            address(INodeReleaseManager(interfold).nodeReleaseRegistry())
        ) {
            revert INodeReleaseRegistry.OnlyNodeReleaseRegistry();
        }
    }

    function _invalidateConfiguration(
        uint256 configurationVersion
    ) private returns (uint256 newVersion) {
        newVersion = configurationVersion + 1;
        BondingEligibilityStorage.EligibilityLayout storage state = _layout();
        // Checkpoint value zero means that no configuration existed yet.
        state.configurationVersions.push(
            uint48(block.timestamp),
            uint208(newVersion + 1)
        );
        state.activeOperatorCounts.push(uint48(block.timestamp), 0);
        BondOwnerCapacityLib.reset(newVersion);
        emit IBondingRegistry.EligibilityConfigurationVersionUpdated(
            newVersion
        );
    }

    function updateOperator(
        address operator,
        bool oldActive,
        OperatorRequirements calldata requirements,
        uint256 configurationVersion,
        uint256 activeOperatorCount
    ) external returns (uint256 newActiveOperatorCount, bool newActive) {
        InterfoldTicketToken ticketToken = InterfoldTicketToken(
            requirements.ticketToken
        );
        address releaseRegistry = address(
            INodeReleaseManager(
                address(ICiphernodeRegistry(requirements.registry).interfold())
            ).nodeReleaseRegistry()
        );
        newActive =
            ticketToken.registry() == address(this) &&
            releaseRegistry.code.length != 0 &&
            INodeReleaseRegistry(releaseRegistry).isNodeReleaseReady(
                operator
            ) &&
            requirements.registered &&
            !requirements.banned &&
            isCiphernodeBonded(
                requirements.ciphernodeBond,
                requirements.requiredCiphernodeBond,
                requirements.ciphernodeBondActiveBps
            ) &&
            ticketToken.balanceOf(operator) / requirements.ticketPrice >=
            requirements.minTicketBalance;
        BondOwnerCapacityLib.sync(
            operator,
            IBondingRegistry(address(this)).bondOwnerOf(operator),
            newActive,
            configurationVersion
        );
        if (oldActive == newActive) {
            return (activeOperatorCount, newActive);
        }

        newActiveOperatorCount = newActive
            ? activeOperatorCount + 1
            : activeOperatorCount - 1;
        BondingEligibilityStorage.EligibilityLayout storage state = _layout();
        state.operatorActiveVersions[operator].push(
            uint48(block.timestamp),
            newActive ? uint208(configurationVersion + 1) : 0
        );
        state.activeOperatorCounts.push(
            uint48(block.timestamp),
            uint208(newActiveOperatorCount)
        );
        emit IBondingRegistry.OperatorActivationChanged(operator, newActive);
    }

    function isCiphernodeBonded(
        uint256 ciphernodeBond,
        uint256 requiredCiphernodeBond,
        uint256 ciphernodeBondActiveBps
    ) public pure returns (bool) {
        return
            ciphernodeBond >=
            Math.mulDiv(
                requiredCiphernodeBond,
                ciphernodeBondActiveBps,
                10_000,
                Math.Rounding.Ceil
            );
    }

    function eligibilityAt(
        address operator,
        uint256 timepoint
    ) external view returns (bool active, uint256 activeOperatorCount) {
        BondingEligibilityStorage.EligibilityLayout storage state = _layout();
        uint48 key = SafeCast.toUint48(timepoint);
        uint208 configurationVersion = state.configurationVersions.upperLookup(
            key
        );
        active =
            configurationVersion != 0 &&
            state.operatorActiveVersions[operator].upperLookup(key) ==
            configurationVersion;
        activeOperatorCount = state.activeOperatorCounts.upperLookup(key);
    }

    /// @notice Returns counted snapshot owners only under the current eligibility policy.
    function committeeOwnerCapacity(
        uint256 timepoint
    ) external view returns (uint256) {
        Checkpoints.Trace208 storage versions = _layout().configurationVersions;
        uint208 version = versions.upperLookupRecent(
            SafeCast.toUint48(timepoint)
        );
        if (version == 0 || version != versions.latest()) return 0;
        return BondOwnerCapacityLib.countAt(timepoint);
    }

    function _layout()
        private
        pure
        returns (BondingEligibilityStorage.EligibilityLayout storage state)
    {
        bytes32 slot = STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            state.slot := slot
        }
    }
}
