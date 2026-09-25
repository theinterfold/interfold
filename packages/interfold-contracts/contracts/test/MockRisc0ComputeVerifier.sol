// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

contract MockRisc0ComputeVerifier {
    error UnexpectedCall();

    bytes32 private expectedCallHash;

    /// @dev Makes `verify` revert unless its calldata equals `data`.
    function expectCall(bytes calldata data) external {
        expectedCallHash = keccak256(data);
    }

    function verify(bytes calldata, bytes32, bytes32) external view {
        if (keccak256(msg.data) != expectedCallHash) revert UnexpectedCall();
    }
}
