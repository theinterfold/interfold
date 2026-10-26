// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IOpenVmReceiptVerifier } from "@interfold/contracts/contracts/interfaces/IOpenVmReceiptVerifier.sol";

/// @notice Unproved execution for isolated local integration tests only.
contract MockOpenVmReceiptVerifier is IOpenVmReceiptVerifier {
  bytes32 public constant imageId = keccak256("INTERFOLD_LOCAL_UNPROVED_TEST");
  function verify(bytes calldata, bytes32, bytes32) external pure override {}
}
