// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ICiphertextVerifier } from "../../interfaces/ICiphertextVerifier.sol";
import { OpenVmComputeProof } from "../../lib/OpenVmComputeProof.sol";

import {
    IOpenVmReceiptVerifier
} from "../../interfaces/IOpenVmReceiptVerifier.sol";

/**
 * @title OpenVmBfvCiphertextVerifier
 * @notice Verifies the protocol fields committed by the BFV compute guest.
 */
contract OpenVmBfvCiphertextVerifier is ICiphertextVerifier {
    error InvalidImageId();
    error InvalidVerifier();

    IOpenVmReceiptVerifier public immutable openVmVerifier;
    bytes32 public immutable imageId;

    constructor(IOpenVmReceiptVerifier verifier, bytes32 guestImageId) {
        if (address(verifier).code.length == 0) revert InvalidVerifier();
        if (guestImageId == bytes32(0)) revert InvalidImageId();
        openVmVerifier = verifier;
        imageId = guestImageId;
    }

    /// @inheritdoc ICiphertextVerifier
    function verify(
        uint256 e3Id,
        bytes32 encryptionSchemeId,
        bytes32 paramsHash,
        bytes32 committeePublicKey,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes calldata encodedProof
    ) external view returns (bool) {
        OpenVmComputeProof.Proof memory proof = OpenVmComputeProof.decode(
            encodedProof
        );
        if (proof.paramsHash != paramsHash) return false;
        openVmVerifier.verify(
            proof.seal,
            imageId,
            _journalDigest(
                e3Id,
                encryptionSchemeId,
                paramsHash,
                committeePublicKey,
                ciphertextOutputHash,
                ciphertextCommitment,
                proof.inputRoot
            )
        );
        return true;
    }

    function _journalDigest(
        uint256 e3Id,
        bytes32 encryptionSchemeId,
        bytes32 paramsHash,
        bytes32 committeePublicKey,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes32 inputRoot
    ) private view returns (bytes32) {
        return
            sha256(
                OpenVmComputeProof.journal(
                    bytes32(block.chainid),
                    bytes32(uint256(uint160(msg.sender))),
                    bytes32(e3Id),
                    encryptionSchemeId,
                    committeePublicKey,
                    ciphertextOutputHash,
                    ciphertextCommitment,
                    paramsHash,
                    inputRoot
                )
            );
    }
}
