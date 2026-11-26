// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    SynchronizedDkgControllerHarness
} from "./SynchronizedDkgRegistryHarness.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { E3 } from "../interfaces/IE3.sol";
import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";
import { InterfoldLifecycle } from "../lib/InterfoldLifecycle.sol";

/// Seed only the disabled request's application/DA checkpoint. Use the real lifecycle's
/// request-bound proof check against the registry that actually accepted the DKG publication.
contract SynchronizedDecryptionControllerHarness is
    SynchronizedDkgControllerHarness
{
    mapping(uint256 => IInterfold.E3Deadlines) private deadlines;

    function seedCiphertext(
        uint256 id,
        bytes32 contentHash,
        bytes32 commitment,
        address verifier
    ) external {
        E3 storage e3 = _requests[id];
        require(getE3Stage(id) == IInterfold.E3Stage.KeyPublished);
        e3.ciphertextOutput = contentHash;
        e3.ciphertextCommitment = commitment;
        e3.decryptionVerifier = IDecryptionVerifier(verifier);
        deadlines[id].decryptionDeadline = block.timestamp + 3600;
        emit IInterfold.CiphertextOutputReferencePublished(
            id,
            contentHash,
            commitment,
            1,
            0
        );
        emit IInterfold.E3StageChanged(
            id,
            IInterfold.E3Stage.KeyPublished,
            IInterfold.E3Stage.CiphertextReady
        );
    }

    function getE3Stage(
        uint256 id
    ) public view override returns (IInterfold.E3Stage) {
        if (_requests[id].plaintextOutput.length != 0)
            return IInterfold.E3Stage.Complete;
        if (deadlines[id].decryptionDeadline != 0)
            return IInterfold.E3Stage.CiphertextReady;
        return super.getE3Stage(id);
    }

    function getDeadlines(
        uint256 id
    ) external view returns (IInterfold.E3Deadlines memory) {
        return deadlines[id];
    }

    function failureCondition(
        uint256 id
    ) external view returns (bool, uint8, uint256) {
        return
            InterfoldLifecycle.failureCondition(
                registries[id],
                id,
                uint8(getE3Stage(id)),
                deadlines[id],
                0
            );
    }

    function publishPlaintextOutput(
        uint256 id,
        bytes calldata output,
        bytes calldata proof
    ) external returns (bool) {
        E3 storage e3 = _requests[id];
        require(
            getE3Stage(id) == IInterfold.E3Stage.CiphertextReady &&
                block.timestamp <= deadlines[id].decryptionDeadline
        );
        InterfoldLifecycle.verifyPlaintext(
            address(e3.decryptionVerifier),
            registries[id],
            id,
            e3.ciphertextOutput,
            e3.committeePublicKey,
            keccak256(output),
            e3.ciphertextCommitment,
            proof
        );
        e3.plaintextOutput = output;
        emit IInterfold.E3StageChanged(
            id,
            IInterfold.E3Stage.CiphertextReady,
            IInterfold.E3Stage.Complete
        );
        return true;
    }
}
