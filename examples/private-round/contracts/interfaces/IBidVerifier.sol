// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice The verifier that `circuits/compile.sh` generates for `private_round_bid` and `private_round_claim`.
interface IBidVerifier {
  function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
