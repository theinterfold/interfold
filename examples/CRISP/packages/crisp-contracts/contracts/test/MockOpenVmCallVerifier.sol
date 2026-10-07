// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Test-only call oracle. This contract does not verify a cryptographic proof.
contract MockOpenVmCallVerifier {
  bytes32 private expectedCall;
  error UnexpectedOpenVmCall();

  function setExpectedCall(bytes calldata publicValues, bytes calldata proofData, bytes32 exeCommit, bytes32 vmCommit) external {
    expectedCall = keccak256(abi.encode(publicValues, proofData, exeCommit, vmCommit));
  }

  function verify(bytes calldata publicValues, bytes calldata proofData, bytes32 exeCommit, bytes32 vmCommit) external view {
    if (keccak256(abi.encode(publicValues, proofData, exeCommit, vmCommit)) != expectedCall) revert UnexpectedOpenVmCall();
  }
}
