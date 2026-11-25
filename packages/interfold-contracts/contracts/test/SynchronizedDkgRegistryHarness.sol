// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    CiphernodeRegistryOwnable
} from "../registry/CiphernodeRegistryOwnable.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { E3 } from "../interfaces/IE3.sol";
import { IPkVerifier } from "../interfaces/IPkVerifier.sol";
import { BfvProtocol } from "../lib/BfvProtocol.sol";
import { DkgPublicationLib } from "../lib/DkgPublicationLib.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";

/// @dev Keep test-only checkpoint setup out of the inherited registry's EIP-170 budget.
library SynchronizedDkgSeedLib {
    function seed(
        ICiphernodeRegistry.Committee storage c,
        address[3] calldata nodes
    ) external {
        require(c.stage == ICiphernodeRegistry.CommitteeStage.None);
        c.stage = ICiphernodeRegistry.CommitteeStage.Finalized;
        c.threshold = [BfvProtocol.MINIMUM_H, BfvProtocol.MINIMUM_N];
        c.activeCount = nodes.length;
        for (uint256 i; i < nodes.length; ++i) {
            c.topNodes.push(nodes[i]);
            c.memberStatus[nodes[i]] = ICiphernodeRegistry.MemberStatus.Active;
        }
    }
}

/// @dev Test-only finalized checkpoint, below disabled request/profile admission.
contract SynchronizedDkgRegistryHarness is CiphernodeRegistryOwnable {
    function seed(
        uint256 e3Id,
        address controller,
        address[3] calldata nodes
    ) external {
        SynchronizedDkgSeedLib.seed(committees[e3Id], nodes);
        _committeeDependencies[e3Id].interfoldContract = IInterfold(controller);
        DkgPublicationLib.establishRequestContext(IInterfold(controller), e3Id);
    }

    function exclude(uint256 e3Id, address node) external {
        committees[e3Id].memberStatus[node] = MemberStatus.Expelled;
    }
}

/// @dev Mock only the lifecycle callback; publication/consent/storage use the real registry.
contract SynchronizedDkgControllerHarness {
    error CallbackRejected();
    mapping(uint256 => E3) internal _requests;
    mapping(uint256 => bytes32) public e3CryptoConfigIds;
    mapping(uint256 => address) public registries;
    bool public reject;

    function configure(
        uint256 e3Id,
        address registry,
        address verifier,
        bytes32 configId
    ) external {
        _requests[e3Id].pkVerifier = IPkVerifier(verifier);
        registries[e3Id] = registry;
        e3CryptoConfigIds[e3Id] = configId;
    }

    function getE3(uint256 e3Id) external view returns (E3 memory) {
        return _requests[e3Id];
    }

    function getE3Stage(
        uint256 e3Id
    ) public view virtual returns (IInterfold.E3Stage) {
        return
            _requests[e3Id].committeePublicKey == bytes32(0)
                ? IInterfold.E3Stage.Requested
                : IInterfold.E3Stage.KeyPublished;
    }

    function setReject(bool value) external {
        reject = value;
    }

    function onCommitteePublished(uint256 e3Id, bytes32 pk) external {
        require(msg.sender == registries[e3Id]);
        if (reject) revert CallbackRejected();
        _requests[e3Id].committeePublicKey = pk;
    }
}
