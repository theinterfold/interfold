// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { Grid } from "./ProbeSearch.sol";

/// @title Clearing of a sealed, one-batch, uniform-price token sale from the revealed budget sums.
/// @notice `F[l]` is the sum of the budgets (budget units) of the counted bids with step `>= l`. Everything is in
/// payment-token base units: `Fb[l] = F[l] * budgetUnit`, and `U = 10^saleDecimals`. Division rounds down,
/// except where `ceil` is written. `sdk/src/clearing.ts` mirrors this file.
///
/// ```text
/// lstar >= 1:  capped iff Fb[lstar] * U >= p[lstar] * S, else uncapped
/// lstar == 0:  capped iff Fb[0] * U >= p[0] * S, else undersubscribed
/// capped at s: pStar = p[s]; above = Fb[s+1] (0 if s+1 == levels); R = S - floor(above * U / pStar);
///              step b > s gets floor(Bb * U / pStar); b < s gets 0; sold = S; the bids at b == s share R first
///              bid first (`marginalFills`): fill_i = min(floor(Bb_i * U / pStar), rest of R)
/// uncapped at l: pStar = ceil(Fb[l] * U / S); b >= l gets floor(Bb * U / pStar); sold = floor(Fb[l] * U / pStar)
/// undersubscribed: pStar = p[0]; everybody gets floor(Bb * U / p[0]); sold = floor(Fb[0] * U / p[0])
/// paid = ceil(tokens * pStar / U) (at most Bb); refund = escrow - paid
/// ```
library SaleClearing {
  uint8 internal constant KIND_UNDERSUBSCRIBED = 0;
  uint8 internal constant KIND_CAPPED = 1;
  uint8 internal constant KIND_UNCAPPED = 2;

  /// @dev What `clear` returns.
  /// @param kind `KIND_UNDERSUBSCRIBED`, `KIND_CAPPED` or `KIND_UNCAPPED`.
  /// @param step The step `k` of the claim proof: `s` (capped), `l` (uncapped), 0 (undersubscribed).
  /// @param pStar The uniform price, in payment-token base units per `U` sale-token base units.
  /// @param sold The sale-token base units sold in total. It never exceeds the supply.
  /// @param remaining `R` (capped only): the sale tokens that the bids at step `s` share, first bid first.
  struct Result {
    uint8 kind;
    uint8 step;
    uint256 pStar;
    uint256 sold;
    uint256 remaining;
  }

  /// @param g The price grid and sizes of the sale.
  /// @param lstar The clearing step of the probe search.
  /// @param sums `F[l]` in budget units at the known levels. The levels `lstar` and `lstar + 1` (when below
  /// `levels`) must be known; `F[0]` must be known when `lstar == 0`.
  function clear(Grid memory g, uint8 lstar, uint256[16] memory sums) public pure returns (Result memory r) {
    uint256 s = g.supply;
    uint256 u = g.saleUnit;
    uint256 here = sums[lstar] * g.budgetUnit;
    if (lstar == 0 && here * u < g.prices[0] * s) {
      r.kind = KIND_UNDERSUBSCRIBED;
      r.pStar = g.prices[0];
      r.sold = (here * u) / r.pStar;
    } else if (here * u >= g.prices[lstar] * s) {
      r.kind = KIND_CAPPED;
      r.step = lstar;
      r.pStar = g.prices[lstar];
      uint256 above = lstar + 1 == g.levels ? 0 : sums[lstar + 1] * g.budgetUnit;
      r.remaining = s - (above * u) / r.pStar;
      r.sold = s;
    } else {
      r.kind = KIND_UNCAPPED;
      r.step = lstar;
      r.pStar = (here * u + s - 1) / s;
      r.sold = (here * u) / r.pStar;
    }
  }

  /// @notice The tokens of an immediate claim with the budget `budget` (payment-token base units) and the comparison
  /// `cmp` of its step with `r.step` (0: below, 1: equal, 2: above). A capped bid at the clearing step (`cmp == 1`)
  /// gets nothing here: its fill comes from `marginalFill` (or it forfeits it, claiming after the marginal window).
  function tokensFor(Result memory r, uint8 cmp, uint256 budget, uint256 saleUnit) internal pure returns (uint256) {
    if (cmp == 0 || (cmp == 1 && r.kind == KIND_CAPPED)) return 0;
    return (budget * saleUnit) / r.pStar;
  }

  /// @notice The most tokens a marginal bid with the budget `budget` can get at `pStar`.
  function fullFill(uint256 budget, uint256 pStar, uint256 saleUnit) internal pure returns (uint256) {
    return (budget * saleUnit) / pStar;
  }

  /// @notice The price of `tokens` sale-token base units at `pStar`, rounded up. It is at most the budget when
  /// `tokens <= budget * unit / pStar`.
  function cost(uint256 tokens, uint256 pStar, uint256 unit) internal pure returns (uint256) {
    return (tokens * pStar + unit - 1) / unit;
  }
}
