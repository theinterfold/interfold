// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity ^0.8.27;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { ERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import { ERC20Votes } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";

/// @title MockVotesToken
/// @notice An ERC20Votes token for exercising `CensusMode.ONCHAIN` and `CreditMode.CUSTOM` rounds.
/// @dev `MockVotingToken`, a plain ERC20, is the negative case for the token probes in
/// `CRISPProgram._initRound`; this one is the positive case.
///
/// Uses the timestamp clock, matching `InterfoldToken`. A round records its snapshot in whatever
/// units the token reports, so a mock on the default block-number clock would exercise a
/// different path from the token this mode is built for.
contract MockVotesToken is ERC20, ERC20Permit, ERC20Votes {
  constructor() ERC20("Mock Votes Token", "MVOTE") ERC20Permit("Mock Votes Token") {
    _mint(msg.sender, 1e24);
    _delegate(msg.sender, msg.sender);
  }

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
    if (delegates(to) == address(0)) _delegate(to, to);
  }

  function clock() public view override returns (uint48) {
    return uint48(block.timestamp);
  }

  /// @dev Declared pure per ERC-6372, so it cannot read `clock()`.
  function CLOCK_MODE() public pure override returns (string memory) {
    return "mode=timestamp";
  }

  function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Votes) {
    super._update(from, to, value);
  }

  function nonces(address owner) public view override(ERC20Permit, Nonces) returns (uint256) {
    return super.nonces(owner);
  }
}
