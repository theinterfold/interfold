// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

library OpenVmComputeProof {
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

    /// @notice Encode the exact nine words whose SHA-256 digest the guest reveals.
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
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                chainId,
                verifyingContract,
                e3Id,
                encryptionSchemeId,
                committeePublicKey,
                ciphertextOutputHash,
                ciphertextCommitment,
                paramsHash,
                inputRoot
            );
    }
}
