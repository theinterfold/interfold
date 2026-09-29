// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

/// @notice The Safe 1.3.0 and 1.4.1 calls that `CRISPProgram` makes. The proxy answers
/// `masterCopy()` itself, from storage, and delegates the other calls to that singleton.
interface ISafe {
  function masterCopy() external view returns (address);

  function getOwners() external view returns (address[] memory);

  function getThreshold() external view returns (uint256);
}
