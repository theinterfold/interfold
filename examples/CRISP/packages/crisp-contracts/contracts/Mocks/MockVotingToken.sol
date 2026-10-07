// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity ^0.8.27;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockVotingToken
/// @notice A mock voting token for testing purposes
/// @dev Public mint grants 1e9 base units to an account that holds none, and caps every balance at
/// `MAX_BALANCE`. A plain ERC20 without checkpoints: it cannot back a round that reads voting
/// power at a snapshot (`CensusMode.ONCHAIN` or `CreditMode.CUSTOM`). Use `MockVotesToken` there.
contract MockVotingToken is ERC20 {
  uint256 public constant MAX_BALANCE = 1e9;

  constructor() ERC20("Mock Voting Token", "MVT") {
    _mint(msg.sender, 1e9);
  }

  function mint(address to, uint256) external {
    if (balanceOf(to) + 1e9 > MAX_BALANCE) {
      // silently fail
      return;
    }
    _mint(to, 1e9);
  }
}
