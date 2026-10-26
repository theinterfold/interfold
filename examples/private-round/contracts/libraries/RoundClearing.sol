// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @title Settlement arithmetic of a private round.
/// @notice Every bidder wants one lot. The decrypted output gives only the outcome and the clearing
/// step `l*`. The price is `prices[l*]` (sold out) or `prices[reserveStep]` (undersubscribed). A bidder
/// pays `cost(tokens) = ceil(tokens * pStar / saleUnit)`. The escrow of every bidder is the price of
/// one lot at the highest step, so `cost(lot) <= escrow` at every price. `sdk/src/clearing.ts` is the
/// TypeScript reference of this library, and `sdk/test-vectors/clearing.json` pins both.
library RoundClearing {
  /// @dev The reserve was not met: everybody gets the escrow back.
  uint8 internal constant NOT_MET = 0;
  /// @dev The reserve was met by fewer bidders than lots: the bidders at or above it get one lot at the reserve price.
  uint8 internal constant UNDERSUBSCRIBED = 1;
  /// @dev `lots` or more bidders accept the clearing step.
  uint8 internal constant SOLD_OUT = 2;
  /// @dev The output was not a valid output of the program: handled like `NOT_MET`.
  uint8 internal constant ABORTED = 3;

  /// @dev The classes of a claim.
  uint8 internal constant CLASS_REFUND = 0;
  uint8 internal constant CLASS_FULL = 1;
  uint8 internal constant CLASS_MARGINAL = 2;

  /// @notice The price of the clearing, or 0 when nothing sells.
  function pStar(uint256[16] storage prices, uint8 outcome, uint8 step, uint8 reserveStep) internal view returns (uint256) {
    if (outcome == SOLD_OUT) return prices[step];
    if (outcome == UNDERSUBSCRIBED) return prices[reserveStep];
    return 0;
  }

  /// @notice The price of `tokens` sale-token base units at `price`, rounded up.
  function cost(uint256 tokens, uint256 price, uint256 unit) internal pure returns (uint256) {
    return (tokens * price + unit - 1) / unit;
  }

  /// @notice The step `k` that a claim proof compares the bid with. `needed` is false when a counted
  /// bidder needs no proof: nothing sells, or the sale is undersubscribed with the reserve at step 0
  /// (every bid is at or above it).
  function claimStep(uint8 outcome, uint8 step, uint8 reserveStep) internal pure returns (bool needed, uint8 k) {
    if (outcome == SOLD_OUT) return (true, step);
    if (outcome == UNDERSUBSCRIBED && reserveStep != 0) return (true, reserveStep - 1);
    return (false, 0);
  }

  /// @notice The class of a bidder, from the comparison `cmp` of the proof (0: `b < k`, 1: `b == k`,
  /// 2: `b > k`). The timing of the phases is not part of it. A bidder that was not counted is refunded.
  function classOf(uint8 outcome, uint8 reserveStep, bool counted, uint8 cmp) internal pure returns (uint8) {
    if (!counted) return CLASS_REFUND;
    if (outcome == SOLD_OUT)
      return
        cmp == 2
          ? CLASS_FULL
          : cmp == 1
            ? CLASS_MARGINAL
            : CLASS_REFUND;
    if (outcome == UNDERSUBSCRIBED) return reserveStep == 0 || cmp == 2 ? CLASS_FULL : CLASS_REFUND;
    return CLASS_REFUND;
  }

  /// @notice The number of registered bidders at the clearing step with a lower bidder index than
  /// `index`. `mask` has the bit `i` set for the registered bidder `i`.
  function marginalRank(uint256 mask, uint256 index) internal pure returns (uint256 rank) {
    uint256 below = mask & ((1 << index) - 1);
    while (below != 0) {
      below &= below - 1;
      rank++;
    }
  }

  /// @notice Whether a registered bidder at the clearing step gets its lot. Lots are never split: the
  /// `R = lots - aboveClaimed` lots that the bidders above the step did not claim go to the registered
  /// bidders in the order of the bidder index, one lot each. `rank` is the number of registered
  /// bidders with a lower index (`marginalRank`). `aboveClaimed < lots`, because fewer than `lots`
  /// bidders are above the clearing step.
  function marginalFilled(uint8 lots, uint256 aboveClaimed, uint256 rank) internal pure returns (bool) {
    return rank < lots - aboveClaimed;
  }
}
