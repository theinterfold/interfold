// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice The verifier `scripts/compile_circuits.sh` generates for `circuits/fold`.
interface IRecordVerifier {
  function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
