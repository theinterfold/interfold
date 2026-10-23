// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";

/// @notice Unit tests only: serves `getE3` to `AuctionProgram` for one fixed window, requester and key.
contract MockInterfold {
  uint256 public immutable inputDeadline;
  bytes32 public immutable committeePublicKey;
  address public immutable requester;

  constructor(uint256 _inputDeadline, bytes32 _committeePublicKey, address _requester) {
    inputDeadline = _inputDeadline;
    committeePublicKey = _committeePublicKey;
    requester = _requester;
  }

  function getE3(uint256) external view returns (E3 memory e3) {
    e3.inputWindow = [uint256(0), inputDeadline];
    e3.committeePublicKey = committeePublicKey;
    e3.requester = requester;
  }
}
