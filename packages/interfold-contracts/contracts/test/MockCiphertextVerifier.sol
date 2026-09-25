// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ICiphertextVerifier } from "../interfaces/ICiphertextVerifier.sol";

contract MockCiphertextVerifier is ICiphertextVerifier {
    error UnexpectedCall();

    bool public result = true;
    bytes32 private expectedCallHash;

    function setResult(bool value) external {
        result = value;
    }

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
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        if (expectedCallHash != 0 && keccak256(msg.data) != expectedCallHash)
            revert UnexpectedCall();
        return result;
    }
}
