// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";

contract MockDecryptionVerifier is IDecryptionVerifier {
    error UnexpectedCall();

    uint256 public constant override threshold = 1;

    /// @dev Test-only: proofs whose first 4 bytes are `0xdeadbeef` revert with
    ///      `InvalidProof` so tests can exercise the wrapper failure path
    ///      (production wrapper now reverts instead of returning false).
    bytes4 private constant _FAIL_MAGIC = 0xdeadbeef;
    bytes4 private constant _RETURN_FALSE_MAGIC = 0xfafafafa;
    bytes32 private expectedCallHash;

    /// @dev Makes `verify` revert unless its calldata equals `data`.
    function expectCall(bytes calldata data) external {
        expectedCallHash = keccak256(data);
    }

    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        bytes calldata proof
    ) external view returns (bool success) {
        if (expectedCallHash != 0 && keccak256(msg.data) != expectedCallHash)
            revert UnexpectedCall();
        if (proof.length >= 4 && bytes4(proof[0:4]) == _FAIL_MAGIC) {
            revert InvalidProof();
        }
        if (proof.length >= 4 && bytes4(proof[0:4]) == _RETURN_FALSE_MAGIC)
            return false;
        if (proof.length == 0) revert InvalidProof();
        success = true;
    }
}
