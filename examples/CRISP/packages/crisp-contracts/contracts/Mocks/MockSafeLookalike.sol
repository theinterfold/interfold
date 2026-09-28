// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

/// @notice Test-only contract that answers the Safe calls with values that it chooses.
/// @dev It reports an accepted singleton and any owner list. `CRISPProgram` must not treat it as a
/// Safe, because its runtime code is not an accepted Safe proxy.
contract MockSafeLookalike {
  address public immutable masterCopy;
  address[] private owners;
  uint256 public immutable getThreshold;

  constructor(address _masterCopy, address[] memory _owners, uint256 _threshold) {
    masterCopy = _masterCopy;
    owners = _owners;
    getThreshold = _threshold;
  }

  function getOwners() external view returns (address[] memory) {
    return owners;
  }
}
