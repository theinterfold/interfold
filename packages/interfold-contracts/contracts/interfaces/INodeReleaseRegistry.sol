// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { IBondingRegistry } from "./IBondingRegistry.sol";
import { ICiphernodeRegistry } from "./ICiphernodeRegistry.sol";

/// @notice Controls which ciphernode compatibility versions can participate in new E3s.
interface INodeReleaseRegistry {
    /// @notice Compatibility values that one operator reports at startup.
    struct OperatorNodeRelease {
        bytes32 releaseId;
        uint32 protocolVersion;
        uint32 nodeGeneration;
    }

    error InvalidNodeRelease();
    error NodeReleasePolicyRegression();
    error NodeReleasePolicyRequiresPause();
    error NodeReleasePolicyInUse(
        uint256 activeE3s,
        uint256 unreleasedCommittees
    );
    error NodeReleaseBindingMismatch();
    error NodeReleaseActivationStale();
    error OnlyNodeReleaseRegistry();
    error RenounceOwnershipDisabled();

    event RequiredNodeReleaseUpdated(
        uint32 previousProtocolVersion,
        uint32 previousNodeGeneration,
        uint32 requiredProtocolVersion,
        uint32 requiredNodeGeneration
    );
    event OperatorNodeReleaseAcknowledged(
        address indexed operator,
        bytes32 indexed releaseId,
        uint32 protocolVersion,
        uint32 nodeGeneration
    );

    /// @notice Copies the current controller's policy before a compatible replacement.
    /// @dev Call this, Interfold.setNodeReleaseRegistry, and any generation increase in one batch.
    function inheritReleasePolicy(INodeReleaseRegistry previous) external;

    /// @notice Sets the minimum compatibility values for new work.
    function setRequiredNodeRelease(
        uint32 protocolVersion,
        uint32 nodeGeneration
    ) external;

    /// @notice Records the caller's release and refreshes its eligibility.
    function acknowledgeNodeRelease(
        bytes32 releaseId,
        uint32 protocolVersion,
        uint32 nodeGeneration
    ) external;

    function requiredProtocolVersion() external view returns (uint32);

    function requiredNodeGeneration() external view returns (uint32);

    function operatorNodeRelease(
        address operator
    ) external view returns (OperatorNodeRelease memory);

    function isNodeReleaseReady(address operator) external view returns (bool);

    function bondingRegistry() external view returns (IBondingRegistry);

    function ciphernodeRegistry() external view returns (ICiphernodeRegistry);

    /// @notice Requires paused requests, no active E3s, and no unreleased committees.
    function assertUpgradeWindow() external view;

    /// @notice Verifies its protocol binding and invalidates cached node eligibility.
    function activate() external;
}
