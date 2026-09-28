// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IHonkVerifier } from "../interfaces/IHonkVerifier.sol";

/// @notice Test-only verifier that accepts exactly one list of public inputs.
/// @dev Lets a test assert which verifier `CRISPProgram` calls and the exact public inputs that it
/// builds, without a real proof. A verifier that the test did not configure rejects every call.
contract MockExpectingHonkVerifier is IHonkVerifier {
  bytes32 public expectedPublicInputsHash;

  error UnexpectedPublicInputs(bytes32 actual, bytes32 expected);

  function setExpectedPublicInputs(bytes32[] calldata publicInputs) external {
    expectedPublicInputsHash = keccak256(abi.encode(publicInputs));
  }

  function verify(bytes calldata, bytes32[] calldata publicInputs) external view returns (bool) {
    bytes32 actual = keccak256(abi.encode(publicInputs));
    if (actual != expectedPublicInputsHash) revert UnexpectedPublicInputs(actual, expectedPublicInputsHash);
    return true;
  }
}
