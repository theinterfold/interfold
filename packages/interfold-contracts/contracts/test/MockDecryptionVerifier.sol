// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";

contract MockDecryptionVerifier is IDecryptionVerifier {
    /// @dev Test-only: proofs whose first 4 bytes are `0xdeadbeef` revert with
    ///      `InvalidProof` so tests can exercise the wrapper failure path
    ///      (production wrapper now reverts instead of returning false).
    bytes4 private constant _FAIL_MAGIC = 0xdeadbeef;

    function verify(
        uint256,
        uint256,
        address[] calldata,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        bytes calldata proof
    ) external pure returns (bool success) {
        if (proof.length >= 4 && bytes4(proof[0:4]) == _FAIL_MAGIC) {
            revert InvalidProof();
        }
        if (proof.length == 0) revert InvalidProof();
        success = true;
    }
}
