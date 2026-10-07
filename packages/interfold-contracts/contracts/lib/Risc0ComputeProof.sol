// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/**
 * @title Risc0ComputeProof
 * @notice Decodes the compute proof and rebuilds the journal of the legacy RISC Zero guest. Kept for
 * the RISC Zero deployments and the rounds that snapshot them; new programs use OpenVmComputeProof.
 */
library Risc0ComputeProof {
    uint256 internal constant FIELD_SIZE = 132;
    uint256 internal constant FIELD_COUNT = 9;

    struct Proof {
        bytes seal;
        bytes32 paramsHash;
        bytes32 inputRoot;
    }

    function decode(bytes memory encoded) internal pure returns (Proof memory) {
        (bytes memory seal, bytes32 paramsHash, bytes32 inputRoot) = abi.decode(
            encoded,
            (bytes, bytes32, bytes32)
        );
        return Proof(seal, paramsHash, inputRoot);
    }

    function journal(
        bytes32 chainId,
        bytes32 verifyingContract,
        bytes32 e3Id,
        bytes32 encryptionSchemeId,
        bytes32 committeePublicKey,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes32 paramsHash,
        bytes32 inputRoot
    ) internal pure returns (bytes memory encoded) {
        encoded = new bytes(FIELD_SIZE * FIELD_COUNT);
        _encodeVec32(encoded, 0, chainId);
        _encodeVec32(encoded, FIELD_SIZE, verifyingContract);
        _encodeVec32(encoded, FIELD_SIZE * 2, e3Id);
        _encodeVec32(encoded, FIELD_SIZE * 3, encryptionSchemeId);
        _encodeVec32(encoded, FIELD_SIZE * 4, committeePublicKey);
        _encodeVec32(encoded, FIELD_SIZE * 5, ciphertextOutputHash);
        _encodeVec32(encoded, FIELD_SIZE * 6, ciphertextCommitment);
        _encodeVec32(encoded, FIELD_SIZE * 7, paramsHash);
        _encodeVec32(encoded, FIELD_SIZE * 8, inputRoot);
    }

    function _encodeVec32(
        bytes memory encoded,
        uint256 offset,
        bytes32 value
    ) private pure {
        encoded[offset] = 0x20;
        for (uint256 i; i < 32; ++i) {
            encoded[offset + 4 + i * 4] = value[i];
        }
    }
}
