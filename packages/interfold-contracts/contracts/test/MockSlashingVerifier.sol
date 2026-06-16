// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ICircuitVerifier } from "../interfaces/ICircuitVerifier.sol";

/// @notice Mock circuit verifier for testing. Returns configurable result.
/// @dev Default returnValue = false means proof is invalid = fault confirmed (slash proceeds).
///      Set returnValue = true to simulate a valid proof = no fault (ProofIsValid revert).
contract MockCircuitVerifier is ICircuitVerifier {
    bool public returnValue;

    function setReturnValue(bool _returnValue) external {
        returnValue = _returnValue;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return returnValue;
    }
}
