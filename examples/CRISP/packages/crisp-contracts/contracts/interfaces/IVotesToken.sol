// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

/// @notice The subset of an ERC20Votes token that CRISP reads.
/// @dev `getPastVotes` is read by `CensusMode.ONCHAIN` eligibility, once per input.
/// `getPastTotalSupply` is read by every `CreditMode.CUSTOM` round when it is requested, to size
/// the voting-power divisor. Both are required. A round that names a token which cannot answer
/// the call it needs is rejected at request time, because every input would otherwise revert after
/// the fee is paid.
interface IVotesToken {
  /// @notice The voting power of an account at a past timepoint.
  /// @param account The account to read.
  /// @param timepoint The timepoint, in the ERC-6372 clock units of the token.
  /// @return The voting power at that timepoint.
  function getPastVotes(address account, uint256 timepoint) external view returns (uint256);

  /// @notice The total supply of voting units at a past timepoint.
  /// @dev CRISP assumes it bounds the sum of every account's voting power at the same timepoint.
  /// ERC20Votes guarantees this.
  /// @param timepoint The timepoint, in the ERC-6372 clock units of the token.
  /// @return The total supply at that timepoint.
  function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}
