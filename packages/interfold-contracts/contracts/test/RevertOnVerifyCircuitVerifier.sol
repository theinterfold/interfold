// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ICircuitVerifier } from "../interfaces/ICircuitVerifier.sol";

/// @notice Test helper: reverts if `verify` is invoked (proves early return in wrappers).
contract RevertOnVerifyCircuitVerifier is ICircuitVerifier {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        revert("verify called");
    }
}
