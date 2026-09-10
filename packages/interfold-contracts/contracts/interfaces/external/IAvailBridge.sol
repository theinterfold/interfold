// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.27;

interface IVectorx {
    function rangeStartBlocks(
        bytes32 rangeHash
    ) external view returns (uint32 startBlock);
}
/// @notice Minimal interface for the official Avail Ethereum bridge.
interface IAvailBridge {
    struct MerkleProofInput {
        bytes32[] dataRootProof;
        bytes32[] leafProof;
        bytes32 rangeHash;
        uint256 dataRootIndex;
        bytes32 blobRoot;
        bytes32 bridgeRoot;
        bytes32 leaf;
        uint256 leafIndex;
    }

    function vectorx() external view returns (IVectorx);

    function verifyBlobLeaf(
        MerkleProofInput calldata input
    ) external view returns (bool);
}
