// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.27;

import {
    IAvailBridge,
    IVectorx
} from "../interfaces/external/IAvailBridge.sol";

contract MockVectorX is IVectorx {
    mapping(bytes32 rangeHash => uint32 startBlock)
        public
        override rangeStartBlocks;

    function setRangeStartBlock(bytes32 rangeHash, uint32 startBlock) external {
        rangeStartBlocks[rangeHash] = startBlock;
    }
}

contract MockAvailBridge is IAvailBridge {
    IVectorx public override vectorx;
    bool public proofValid = true;

    constructor(IVectorx initialVectorX) {
        vectorx = initialVectorX;
    }

    function setVectorX(IVectorx nextVectorX) external {
        vectorx = nextVectorX;
    }

    function setProofValid(bool valid) external {
        proofValid = valid;
    }

    function verifyBlobLeaf(
        MerkleProofInput calldata
    ) external view override returns (bool) {
        return proofValid;
    }
}
