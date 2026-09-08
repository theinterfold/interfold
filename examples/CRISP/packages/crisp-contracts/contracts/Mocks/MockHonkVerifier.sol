// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IHonkVerifier } from "../interfaces/IHonkVerifier.sol";

/// @notice Test-only verifier for lifecycle tests that do not exercise Noir.
contract MockHonkVerifier is IHonkVerifier {
  function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
    return true;
  }
}
