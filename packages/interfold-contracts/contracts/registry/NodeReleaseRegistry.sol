// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { INodeReleaseManager } from "../interfaces/INodeReleaseManager.sol";
import { INodeReleaseRegistry } from "../interfaces/INodeReleaseRegistry.sol";

/// @notice Governance policy for ciphernode compatibility versions.
/// @dev Acknowledgement prevents accidental stale participation. It does not prove which binary a
///      malicious operator runs.
contract NodeReleaseRegistry is INodeReleaseRegistry, Ownable2Step {
    // solhint-disable-next-line immutable-vars-naming
    IBondingRegistry public immutable bondingRegistry;
    // solhint-disable-next-line immutable-vars-naming
    ICiphernodeRegistry public immutable ciphernodeRegistry;

    uint32 public requiredProtocolVersion;
    uint32 public requiredNodeGeneration;

    uint256 private _inheritedEligibilityVersion;
    bool private _hasInheritedPolicy;

    mapping(address operator => OperatorNodeRelease release)
        private _operatorNodeReleases;

    constructor(
        address owner,
        IBondingRegistry bonding,
        ICiphernodeRegistry ciphernodeRegistry_
    ) Ownable(owner) {
        if (
            owner == address(0) ||
            address(bonding).code.length == 0 ||
            address(ciphernodeRegistry_).code.length == 0
        ) revert InvalidNodeRelease();
        bondingRegistry = bonding;
        ciphernodeRegistry = ciphernodeRegistry_;
    }

    /// @inheritdoc INodeReleaseRegistry
    function inheritReleasePolicy(
        INodeReleaseRegistry previous
    ) external onlyOwner {
        if (requiredProtocolVersion != 0 || requiredNodeGeneration != 0) {
            revert NodeReleasePolicyRegression();
        }
        INodeReleaseManager interfold = INodeReleaseManager(
            address(ciphernodeRegistry.interfold())
        );
        if (
            address(previous) == address(0) ||
            address(previous) == address(this) ||
            address(interfold.nodeReleaseRegistry()) != address(previous) ||
            address(previous.bondingRegistry()) != address(bondingRegistry) ||
            address(previous.ciphernodeRegistry()) !=
            address(ciphernodeRegistry)
        ) revert NodeReleaseBindingMismatch();
        _assertPausedAndIdle();
        uint32 protocolVersion = previous.requiredProtocolVersion();
        uint32 nodeGeneration = previous.requiredNodeGeneration();
        if (protocolVersion == 0 || nodeGeneration == 0) {
            revert InvalidNodeRelease();
        }

        requiredProtocolVersion = protocolVersion;
        requiredNodeGeneration = nodeGeneration;
        _inheritedEligibilityVersion = bondingRegistry
            .eligibilityConfigurationVersion();
        _hasInheritedPolicy = true;
        emit RequiredNodeReleaseUpdated(0, 0, protocolVersion, nodeGeneration);
    }

    /// @notice Disabled so release administration always has a recoverable owner.
    function renounceOwnership() public pure override {
        revert RenounceOwnershipDisabled();
    }

    function setRequiredNodeRelease(
        uint32 protocolVersion,
        uint32 nodeGeneration
    ) external onlyOwner {
        if (protocolVersion == 0 || nodeGeneration == 0) {
            revert InvalidNodeRelease();
        }
        uint32 previousProtocolVersion = requiredProtocolVersion;
        uint32 previousNodeGeneration = requiredNodeGeneration;
        if (
            protocolVersion < previousProtocolVersion ||
            nodeGeneration < previousNodeGeneration ||
            (protocolVersion == previousProtocolVersion &&
                nodeGeneration == previousNodeGeneration)
        ) revert NodeReleasePolicyRegression();
        if (protocolVersion == previousProtocolVersion) {
            _assertPausedAndIdle();
        } else {
            assertUpgradeWindow();
        }
        requiredProtocolVersion = protocolVersion;
        requiredNodeGeneration = nodeGeneration;
        if (previousProtocolVersion != 0) {
            bondingRegistry.refreshOperatorStatus(address(0));
        }
        emit RequiredNodeReleaseUpdated(
            previousProtocolVersion,
            previousNodeGeneration,
            protocolVersion,
            nodeGeneration
        );
    }

    function acknowledgeNodeRelease(
        bytes32 releaseId,
        uint32 protocolVersion,
        uint32 nodeGeneration
    ) external {
        if (
            releaseId == bytes32(0) ||
            protocolVersion == 0 ||
            nodeGeneration == 0
        ) {
            revert InvalidNodeRelease();
        }
        _operatorNodeReleases[msg.sender] = OperatorNodeRelease(
            releaseId,
            protocolVersion,
            nodeGeneration
        );
        emit OperatorNodeReleaseAcknowledged(
            msg.sender,
            releaseId,
            protocolVersion,
            nodeGeneration
        );
        if (bondingRegistry.isRegistered(msg.sender)) {
            bondingRegistry.refreshOperatorStatus(msg.sender);
        }
    }

    function isNodeReleaseReady(address operator) public view returns (bool) {
        OperatorNodeRelease storage release = _operatorNodeReleases[operator];
        return
            requiredProtocolVersion != 0 &&
            requiredNodeGeneration != 0 &&
            release.protocolVersion == requiredProtocolVersion &&
            release.nodeGeneration >= requiredNodeGeneration;
    }

    function operatorNodeRelease(
        address operator
    ) external view returns (OperatorNodeRelease memory) {
        return _operatorNodeReleases[operator];
    }

    function assertUpgradeWindow() public view {
        _assertPausedAndIdle();
        uint256 unreleasedCommittees = ciphernodeRegistry
            .unreleasedCommitteeCount();
        if (unreleasedCommittees != 0) {
            revert NodeReleasePolicyInUse(0, unreleasedCommittees);
        }
    }

    function activate() external {
        INodeReleaseManager interfold = INodeReleaseManager(
            address(ciphernodeRegistry.interfold())
        );
        if (
            msg.sender != address(interfold) ||
            address(interfold.nodeReleaseRegistry()) != address(this) ||
            address(interfold.bondingRegistry()) != address(bondingRegistry) ||
            address(interfold.ciphernodeRegistry()) !=
            address(ciphernodeRegistry)
        ) revert NodeReleaseBindingMismatch();

        if (_hasInheritedPolicy) {
            // Another policy change or controller activation invalidates this replacement.
            if (
                bondingRegistry.eligibilityConfigurationVersion() !=
                _inheritedEligibilityVersion
            ) revert NodeReleaseActivationStale();
            _assertPausedAndIdle();
        } else {
            assertUpgradeWindow();
        }
        bondingRegistry.refreshOperatorStatus(address(0));
    }

    function _assertPausedAndIdle() private view {
        if (!ciphernodeRegistry.interfold().requestsPaused()) {
            revert NodeReleasePolicyRequiresPause();
        }
        uint256 activeE3s = ciphernodeRegistry.interfold().activeE3Count();
        if (activeE3s != 0) {
            revert NodeReleasePolicyInUse(
                activeE3s,
                ciphernodeRegistry.unreleasedCommitteeCount()
            );
        }
    }
}
