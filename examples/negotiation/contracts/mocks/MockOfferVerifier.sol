// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IOfferVerifier } from "../interfaces/IOfferVerifier.sol";

/// @notice Unit tests only. It accepts the proof `0x01`, and it reverts on any other proof as a Honk
/// verifier does. `setAccepting(false)` makes it return `false`. A test can pin the public inputs it
/// expects: any other inputs revert. It stores the public inputs of the last call.
contract MockOfferVerifier is IOfferVerifier {
  /// @notice `keccak256(abi.encodePacked(publicInputs))` that `verify` requires, or zero for any.
  bytes32 public expectedInputsHash;
  /// @notice Whether `verify` returns `true` for the proof `0x01`.
  bool public accepting = true;

  error ProofRejected();
  error PublicInputsMismatch();

  function expect(bytes32[] calldata publicInputs) external {
    expectedInputsHash = keccak256(abi.encodePacked(publicInputs));
  }

  /// @notice Accept any public inputs again.
  function reset() external {
    expectedInputsHash = bytes32(0);
  }

  function setAccepting(bool value) external {
    accepting = value;
  }

  function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view override returns (bool) {
    if (proof.length != 1 || proof[0] != 0x01) revert ProofRejected();
    if (expectedInputsHash != bytes32(0) && keccak256(abi.encodePacked(publicInputs)) != expectedInputsHash) {
      revert PublicInputsMismatch();
    }
    return accepting;
  }
}
