// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IHonkVerifier } from "../interfaces/IHonkVerifier.sol";

/// @notice Test-only verifier for lifecycle tests that do not exercise Noir.
contract MockHonkVerifier is IHonkVerifier {
  bool public checkPublicKey;
  bytes32 public expectedPublicKey;

  function setExpectedPublicKey(bytes32 commitment) external {
    checkPublicKey = true;
    expectedPublicKey = commitment;
  }

  function verify(bytes calldata, bytes32[] calldata publicInputs) external view returns (bool) {
    return !checkPublicKey || (publicInputs.length == 9 && publicInputs[8] == expectedPublicKey);
  }
}
