// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import {
    IDataAvailabilityVerifier
} from "../interfaces/IDataAvailabilityVerifier.sol";
import {
    IAvailBridge,
    IVectorx
} from "../interfaces/external/IAvailBridge.sol";

/// @notice Verifies Avail blob inclusion through the official VectorX bridge.
/// @dev The expected bridge and VectorX contracts are immutable. If Avail governance rotates the
/// bridge's VectorX pointer, this adapter fails closed and a new E3 program must be deployed.
contract AvailVectorXDataAvailabilityVerifier is IDataAvailabilityVerifier {
    IAvailBridge public immutable bridge;
    IVectorx public immutable vectorx;

    error InvalidBridge();
    error InvalidVectorX();
    error ContentHashMismatch(bytes32 expected, bytes32 actual);
    error InvalidAvailabilityProof();
    error DataRootIndexTooLarge(uint256 value);
    error LeafIndexTooLarge(uint256 value);
    error BlockNumberOverflow();

    constructor(IAvailBridge _bridge, IVectorx _vectorx) {
        if (address(_bridge).code.length == 0) revert InvalidBridge();
        if (address(_vectorx).code.length == 0) revert InvalidVectorX();
        if (address(_bridge.vectorx()) != address(_vectorx))
            revert InvalidVectorX();
        bridge = _bridge;
        vectorx = _vectorx;
    }

    /// @inheritdoc IDataAvailabilityVerifier
    function verifyDataAvailability(
        bytes32 expectedContentHash,
        bytes calldata proof
    ) external view returns (DataReference memory receipt) {
        // Re-check on every proof. A bridge-side verifier rotation must not silently change the
        // trust root of an already deployed CRISP program.
        if (address(bridge.vectorx()) != address(vectorx))
            revert InvalidVectorX();

        IAvailBridge.MerkleProofInput memory input = abi.decode(
            proof,
            (IAvailBridge.MerkleProofInput)
        );
        // The bridge proof exposes the first hash of the raw payload. The official bridge hashes
        // `input.leaf` again when it verifies the submitted-data Merkle tree.
        if (input.leaf != expectedContentHash) {
            revert ContentHashMismatch(expectedContentHash, input.leaf);
        }
        if (!bridge.verifyBlobLeaf(input)) revert InvalidAvailabilityProof();
        if (input.dataRootIndex > type(uint32).max) {
            revert DataRootIndexTooLarge(input.dataRootIndex);
        }
        if (input.leafIndex > type(uint128).max) {
            revert LeafIndexTooLarge(input.leafIndex);
        }

        uint256 blockNumber = uint256(
            vectorx.rangeStartBlocks(input.rangeHash)
        ) +
            input.dataRootIndex +
            1;
        if (blockNumber > type(uint32).max) revert BlockNumberOverflow();

        receipt = DataReference({
            contentHash: expectedContentHash,
            blockNumber: uint32(blockNumber),
            leafIndex: uint128(input.leafIndex)
        });
    }
}
