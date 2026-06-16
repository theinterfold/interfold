// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";

contract MockCiphernodeRegistry is ICiphernodeRegistry {
    /// @notice Configurable committee members per E3 for testing
    mapping(uint256 e3Id => address[] nodes) private _committeeNodes;

    /// @notice Configurable threshold M per E3 for testing
    mapping(uint256 e3Id => uint32 threshold) private _thresholdM;
    uint256 private _accusationVoteValidity = 30 minutes;
    mapping(uint256 e3Id => uint256[] partyIds) private _dkgPartyIds;
    mapping(uint256 e3Id => bytes32[] skAggCommits) private _dkgSkAggCommits;
    mapping(uint256 e3Id => bytes32[] esmAggCommits) private _dkgEsmAggCommits;

    /// @notice Set committee members for an E3 (test helper)
    function setCommitteeNodes(
        uint256 e3Id,
        address[] calldata nodes
    ) external {
        delete _committeeNodes[e3Id];
        for (uint256 i = 0; i < nodes.length; i++) {
            _committeeNodes[e3Id].push(nodes[i]);
        }
    }

    /// @notice Set the threshold M for an E3 (test helper)
    function setThreshold(uint256 e3Id, uint32 m) external {
        _thresholdM[e3Id] = m;
    }

    /// @notice Set DKG anchors for an E3 (test helper)
    function setDkgAnchors(
        uint256 e3Id,
        uint256[] calldata partyIds,
        bytes32[] calldata skAggCommits,
        bytes32[] calldata esmAggCommits
    ) external {
        delete _dkgPartyIds[e3Id];
        delete _dkgSkAggCommits[e3Id];
        delete _dkgEsmAggCommits[e3Id];
        for (uint256 i = 0; i < partyIds.length; i++) {
            _dkgPartyIds[e3Id].push(partyIds[i]);
        }
        for (uint256 i = 0; i < skAggCommits.length; i++) {
            _dkgSkAggCommits[e3Id].push(skAggCommits[i]);
        }
        for (uint256 i = 0; i < esmAggCommits.length; i++) {
            _dkgEsmAggCommits[e3Id].push(esmAggCommits[i]);
        }
    }

    function requestCommittee(
        uint256,
        uint256,
        uint32[2] calldata
    ) external pure returns (bool success) {
        success = true;
    }

    function getCommitteeDeadline(uint256) external view returns (uint256) {
        return block.timestamp + 10;
    }

    function isEnabled(address) external pure returns (bool) {
        return true;
    }

    function committeePublicKey(uint256 e3Id) external pure returns (bytes32) {
        if (e3Id == type(uint256).max) {
            return bytes32(0);
        } else {
            return keccak256(abi.encode(e3Id));
        }
    }

    function isCiphernodeEligible(address) external pure returns (bool) {
        return false;
    }

    // solhint-disable-next-line no-empty-blocks
    function addCiphernode(address) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function removeCiphernode(address) external pure {}

    function publishCommittee(
        uint256,
        bytes calldata,
        bytes32,
        bytes calldata,
        bytes calldata
    ) external pure {} // solhint-disable-line no-empty-blocks

    function getCommitteeNodes(
        uint256 e3Id
    ) external view returns (address[] memory) {
        return _committeeNodes[e3Id];
    }

    function getCommitteeHash(uint256 e3Id) external view returns (bytes32) {
        return keccak256(abi.encodePacked(_committeeNodes[e3Id]));
    }

    function getDkgAnchors(
        uint256 e3Id
    )
        external
        view
        returns (
            uint256[] memory partyIds,
            bytes32[] memory skAggCommits,
            bytes32[] memory esmAggCommits
        )
    {
        return (
            _dkgPartyIds[e3Id],
            _dkgSkAggCommits[e3Id],
            _dkgEsmAggCommits[e3Id]
        );
    }

    function root() external pure returns (uint256) {
        return 0;
    }

    function rootAt(uint256) external pure returns (uint256) {
        return 0;
    }

    function treeSize() external pure returns (uint256) {
        return 0;
    }

    function getBondingRegistry() external pure returns (address) {
        return address(0);
    }

    // solhint-disable-next-line no-empty-blocks
    function setInterfold(IInterfold) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function setBondingRegistry(IBondingRegistry) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function submitTicket(uint256, uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function finalizeCommittee(uint256) external pure returns (bool) {
        return true;
    }

    function sortitionSubmissionWindow() external pure returns (uint256) {
        return 0;
    }

    function accusationVoteValidity() external view returns (uint256) {
        return _accusationVoteValidity;
    }

    function setAccusationVoteValidity(uint256 v) external {
        _accusationVoteValidity = v;
    }

    // solhint-disable-next-line no-empty-blocks
    function proposeAccusationVoteValidity(uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function commitAccusationVoteValidity(uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function cancelAccusationVoteValidityProposal() external pure {}

    // solhint-disable-next-line no-empty-blocks
    function setSortitionSubmissionWindow(uint256) external pure {}

    function isOpen(uint256) external pure returns (bool) {
        return false;
    }

    function expelCommitteeMember(
        uint256 e3Id,
        address member,
        bytes32
    ) external returns (uint256, uint32) {
        address[] storage nodes = _committeeNodes[e3Id];
        for (uint256 i = 0; i < nodes.length; i++) {
            if (nodes[i] == member) {
                nodes[i] = nodes[nodes.length - 1];
                nodes.pop();
                break;
            }
        }
        uint32 m = _thresholdM[e3Id];
        return (nodes.length, m);
    }

    function isCommitteeMemberActive(
        uint256 e3Id,
        address node
    ) external view returns (bool) {
        address[] storage nodes = _committeeNodes[e3Id];
        for (uint256 i = 0; i < nodes.length; i++) {
            if (nodes[i] == node) return true;
        }
        return false;
    }

    function isCommitteeMember(
        uint256 e3Id,
        address node
    ) external view returns (bool) {
        address[] storage nodes = _committeeNodes[e3Id];
        for (uint256 i = 0; i < nodes.length; i++) {
            if (nodes[i] == node) return true;
        }
        return false;
    }

    function canonicalCommitteeNodeAt(
        uint256 e3Id,
        uint256 partyId
    ) external view returns (address) {
        address[] storage nodes = _committeeNodes[e3Id];
        require(
            partyId < nodes.length,
            PartyIdOutOfBounds(partyId, nodes.length)
        );
        return nodes[partyId];
    }

    function getActiveCommitteeNodes(
        uint256
    ) external pure returns (address[] memory nodes, uint256[] memory scores) {
        nodes = new address[](0);
        scores = new uint256[](0);
    }

    function getCommitteeViability(
        uint256 e3Id
    ) external view returns (uint256, uint32, uint32, bool) {
        uint32 m = _thresholdM[e3Id];
        uint32 n = uint32(_committeeNodes[e3Id].length);
        return (n, m, n, n >= m && m > 0);
    }
}

contract MockCiphernodeRegistryEmptyKey is ICiphernodeRegistry {
    function requestCommittee(
        uint256,
        uint256,
        uint32[2] calldata
    ) external pure returns (bool success) {
        success = true;
    }

    function getCommitteeDeadline(uint256) external view returns (uint256) {
        return block.timestamp + 10;
    }

    function isEnabled(address) external pure returns (bool) {
        return true;
    }

    function committeePublicKey(uint256) external pure returns (bytes32) {
        revert CommitteeNotPublished();
    }

    function isCiphernodeEligible(address) external pure returns (bool) {
        return false;
    }

    // solhint-disable-next-line no-empty-blocks
    function addCiphernode(address) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function removeCiphernode(address) external pure {}

    function publishCommittee(
        uint256,
        bytes calldata,
        bytes32,
        bytes calldata,
        bytes calldata
    ) external pure {} // solhint-disable-line no-empty-blocks

    function getCommitteeNodes(
        uint256
    ) external pure returns (address[] memory) {
        address[] memory nodes = new address[](0);
        return nodes;
    }

    function getCommitteeHash(uint256) external pure returns (bytes32) {
        return bytes32(0);
    }

    function getDkgAnchors(
        uint256
    )
        external
        pure
        returns (
            uint256[] memory partyIds,
            bytes32[] memory skAggCommits,
            bytes32[] memory esmAggCommits
        )
    {
        return (partyIds, skAggCommits, esmAggCommits);
    }

    function root() external pure returns (uint256) {
        return 0;
    }

    function rootAt(uint256) external pure returns (uint256) {
        return 0;
    }

    function treeSize() external pure returns (uint256) {
        return 0;
    }

    function getBondingRegistry() external pure returns (address) {
        return address(0);
    }

    // solhint-disable-next-line no-empty-blocks
    function setInterfold(IInterfold) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function setBondingRegistry(IBondingRegistry) external pure {}

    function sortitionSubmissionWindow() external pure returns (uint256) {
        return 0;
    }

    function accusationVoteValidity() external pure returns (uint256) {
        return 30 minutes;
    }

    // solhint-disable-next-line no-empty-blocks
    function setAccusationVoteValidity(uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function proposeAccusationVoteValidity(uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function commitAccusationVoteValidity(uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function cancelAccusationVoteValidityProposal() external pure {}

    // solhint-disable-next-line no-empty-blocks
    function setSortitionSubmissionWindow(uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function submitTicket(uint256, uint256) external pure {}

    // solhint-disable-next-line no-empty-blocks
    function finalizeCommittee(uint256) external pure returns (bool) {
        return true;
    }

    function isOpen(uint256) external pure returns (bool) {
        return false;
    }

    // solhint-disable-next-line no-empty-blocks
    function expelCommitteeMember(
        uint256,
        address,
        bytes32
    ) external pure returns (uint256, uint32) {
        return (0, 0);
    }

    function isCommitteeMemberActive(
        uint256,
        address
    ) external pure returns (bool) {
        return false;
    }

    function isCommitteeMember(uint256, address) external pure returns (bool) {
        return false;
    }

    function canonicalCommitteeNodeAt(
        uint256,
        uint256
    ) external pure returns (address) {
        return address(0);
    }

    function getActiveCommitteeNodes(
        uint256
    ) external pure returns (address[] memory nodes, uint256[] memory scores) {
        nodes = new address[](0);
        scores = new uint256[](0);
    }

    function getCommitteeViability(
        uint256
    ) external pure returns (uint256, uint32, uint32, bool) {
        return (0, 0, 0, false);
    }
}
