// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { LazyIMTData } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { ITokenLaunch } from "../interfaces/ITokenLaunch.sol";
import { Sale } from "./SaleConfig.sol";

/// @notice The progress of a sale, in one slot.
struct Progress {
  uint64 marginalDeadline;
  uint64 claimDeadline;
  uint32 bidCount;
  uint16 probeMask2;
  uint8 lo;
  uint8 hi;
  bool probed;
  bool cleared;
  bool swept;
  bool supplyRefunded;
  bool unsoldWithdrawn;
  bool forfeitedWithdrawn;
  ITokenLaunch.AbortReason abortReason;
}

/// @notice The payment-token and sale-token amounts that the program holds for a sale, by purpose.
struct Accounts {
  /// @dev The escrows of all bids.
  uint256 escrowTotal;
  /// @dev The escrows of the bids that were not counted. Known after `clear`.
  uint256 droppedEscrow;
  /// @dev The escrows of the claims.
  uint256 escrowClaimed;
  /// @dev The payments of the claims, not yet withdrawn by the creator.
  uint256 proceeds;
  /// @dev The sale tokens paid to claimants.
  uint256 tokensClaimed;
  /// @dev The escrows that the creator takes after a counted-set mismatch.
  uint256 forfeitedEscrow;
}

/// @notice The clearing of a sale, stored by `clear`.
struct Cleared {
  uint8 kind;
  uint8 step;
  uint256 pStar;
  uint256 sold;
  /// @dev `R`: the sale tokens that the marginal bids share (capped only).
  uint256 remaining;
  uint256 countedMask;
  uint256 root;
}

/// @notice One bid: sender, escrow tier, and whether the escrow went back.
struct Bid {
  address bidder;
  uint8 tier;
  bool refunded;
}

/// @notice A marginal claim that registered inside the marginal window.
struct Marginal {
  address recipient;
  uint16 budgetUnits;
  uint16 escrowUnits;
  bool registered;
  bool paid;
}

/// @notice Everything that `TokenLaunchProgram` stores for one sale. The libraries take a pointer to it.
struct SaleState {
  Sale sale;
  Progress progress;
  Accounts accounts;
  Cleared cleared;
  /// @dev The claim tree, depth 7. Leaf `i` is the commitment of bid `i`.
  LazyIMTData claimTree;
  /// @dev The E3 id of round 2, 0 until it is linked (E3 id 0 is never a round 2).
  uint256 roundTwo;
  /// @dev The bids counted in round 1.
  uint256 counted1;
  /// @dev The bids that were counted in exactly one round: their escrow is forfeited.
  uint256 forfeitMask;
  /// @dev The revealed round-1 sums in budget units (at most 4095 * 85, so 32 bits are enough).
  uint32[16] sums1;
  mapping(uint256 index => Bid) bids;
  mapping(address bidder => bool) hasBid;
  mapping(bytes32 nullifier => bool) nullifiers;
  mapping(uint256 index => Marginal) marginals;
}
