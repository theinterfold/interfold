// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Decides which addresses may bid in a round. A round names one gate at creation.
/// @dev The gate keys its state by `(msg.sender, e3Id)`: `msg.sender` is the `PrivateRoundProgram`.
interface IBidderGate {
  /// @notice Called by the program once per round, when the round is created.
  /// @param e3Id The round.
  /// @param config The creator's gate configuration, as the gate defines it.
  function configure(uint256 e3Id, bytes calldata config) external;

  /// @notice Called by the program as a view, on every bid.
  /// @param e3Id The round.
  /// @param bidder The address that the bid is for.
  /// @param proof The bidder's proof of eligibility, as the gate defines it.
  function isEligible(uint256 e3Id, address bidder, bytes calldata proof) external view returns (bool);
}
