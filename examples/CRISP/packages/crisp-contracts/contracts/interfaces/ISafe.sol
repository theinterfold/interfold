// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

/// @notice The part of a Safe that `CRISPProgram` reads to authorise a ballot.
/// @dev Safe 1.3.0 and 1.4.1 declare both functions on the singleton, and the proxy delegates them.
interface ISafe {
  /// @notice The owners of the Safe, in the order of its internal owner list.
  /// @return The owner addresses.
  function getOwners() external view returns (address[] memory);

  /// @notice The number of owner signatures that the Safe requires.
  /// @return The threshold.
  function getThreshold() external view returns (uint256);
}

/// @notice The one function that a Safe proxy answers itself instead of delegating.
/// @dev `SafeProxy` returns its singleton address from storage slot 0 for this selector. Its runtime
/// code does not depend on the singleton, so an allowlisted proxy code hash plus an allowlisted
/// singleton identify a genuine Safe.
interface ISafeProxy {
  /// @notice The singleton that the proxy delegates every other call to.
  /// @return The singleton address.
  function masterCopy() external view returns (address);
}
