// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IBidVerifier } from "../interfaces/IBidVerifier.sol";

/// @notice Unit tests only. Accepts the proof `0x01`, and reverts on any other proof as a Honk
/// verifier does. A test can pin the public inputs it expects: any other inputs revert.
contract MockBidVerifier is IBidVerifier {
  /// @notice `keccak256(abi.encodePacked(publicInputs))` that `verify` requires, or zero for any.
  bytes32 public expectedInputsHash;

  error ProofRejected();
  error PublicInputsMismatch();

  function expect(bytes32[] calldata publicInputs) external {
    expectedInputsHash = keccak256(abi.encodePacked(publicInputs));
  }

  function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view override returns (bool) {
    if (proof.length != 1 || proof[0] != 0x01) revert ProofRejected();
    if (expectedInputsHash != bytes32(0) && keccak256(abi.encodePacked(publicInputs)) != expectedInputsHash) {
      revert PublicInputsMismatch();
    }
    return true;
  }
}
