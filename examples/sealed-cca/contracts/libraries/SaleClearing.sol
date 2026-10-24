// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @title Clearing of a sealed, one-batch, uniform-price token sale.
/// @notice The demand curve `c[l]` is the number of counted bidders with a maximum price step `b >= l`.
/// Every bid escrows the same amount `escrow` (E) of the payment token. A bidder who is active at a
/// price `p` buys `E * U / p` sale-token base units, where `U = 10^saleDecimals`. All values are
/// integers. See the README for the case analysis and the rounding rules.
library SaleClearing {
  uint8 internal constant KIND_UNDERSUBSCRIBED = 0;
  uint8 internal constant KIND_CAPPED = 1;
  uint8 internal constant KIND_UNCAPPED = 2;
  uint256 internal constant MAX_LEVELS = 16;

  /// @dev What `clear` returns.
  /// @param kind `KIND_UNDERSUBSCRIBED`, `KIND_CAPPED` or `KIND_UNCAPPED`.
  /// @param step The step `k` that the claim proof compares with: `s` (capped) or `l` (uncapped). 0 when undersubscribed.
  /// @param pStar The uniform price, in payment-token base units per `U` sale-token base units.
  /// @param fullTokens The sale-token base units of a bidder who is filled in full.
  /// @param marginalTokens The sale-token base units of a marginal bidder (capped only).
  /// @param sold The sale-token base units sold in total. It never exceeds the supply.
  struct Result {
    uint8 kind;
    uint8 step;
    uint256 pStar;
    uint256 fullTokens;
    uint256 marginalTokens;
    uint256 sold;
  }

  /// @param prices The prices of the steps. Only the first `levels` are read.
  /// @param levels The number of price steps, 2 to 16.
  /// @param c The demand curve. `c[l]` for `l < levels` must not increase with `l`; `c[levels]` is 0.
  /// @param supply The sale-token base units to sell (S).
  /// @param escrow The payment-token base units of one bid (E).
  /// @param unit `U`, one whole sale token in base units.
  function clear(
    uint256[16] memory prices,
    uint8 levels,
    uint256[16] memory c,
    uint256 supply,
    uint256 escrow,
    uint256 unit
  ) public pure returns (Result memory r) {
    uint256 eu = escrow * unit;
    // Bidders with `b >= l` over-demand just above `p[l-1]` when `c[l] * E * U > p[l-1] * S`.
    for (uint256 l = levels - 1; l >= 1; l--) {
      uint256 demand = c[l] * eu;
      if (demand > prices[l - 1] * supply) {
        if (demand >= prices[l] * supply) {
          return _capped(prices, c, levels, uint8(l), supply, eu);
        }
        // Uncapped: the price is `ceil(c[l] * E * U / S)`. Rounding up keeps `c[l] * (E * U / pStar) <= S`.
        r.kind = KIND_UNCAPPED;
        r.step = uint8(l);
        r.pStar = (demand + supply - 1) / supply;
        r.fullTokens = eu / r.pStar;
        r.sold = c[l] * r.fullTokens;
        return r;
      }
    }
    if (c[0] * eu >= prices[0] * supply) {
      return _capped(prices, c, levels, 0, supply, eu);
    }
    r.kind = KIND_UNDERSUBSCRIBED;
    r.pStar = prices[0];
    r.fullTokens = eu / r.pStar;
    r.sold = c[0] * r.fullTokens;
  }

  /// @dev Capped at step `s`: the price is `p[s]`. The bidders above `s` are filled in full. The
  /// bidders at `s` share what is left, and nobody gets more than a full fill.
  function _capped(
    uint256[16] memory prices,
    uint256[16] memory c,
    uint8 levels,
    uint8 s,
    uint256 supply,
    uint256 eu
  ) private pure returns (Result memory r) {
    r.kind = KIND_CAPPED;
    r.step = s;
    r.pStar = prices[s];
    r.fullTokens = eu / r.pStar;
    uint256 above = s + 1 < levels ? c[s + 1] : 0;
    uint256 marginal = c[s] - above;
    uint256 remaining = supply - above * r.fullTokens;
    if (marginal != 0) {
      uint256 share = remaining / marginal;
      r.marginalTokens = share < r.fullTokens ? share : r.fullTokens;
    }
    r.sold = above * r.fullTokens + marginal * r.marginalTokens;
  }

  /// @notice The price of `tokens` sale-token base units at `pStar`, rounded up. It is at most the
  /// escrow when `tokens <= escrow * unit / pStar`.
  function cost(uint256 tokens, uint256 pStar, uint256 unit) internal pure returns (uint256) {
    return (tokens * pStar + unit - 1) / unit;
  }

  /// @notice The tokens a bidder gets, from the comparison `cmp` of the bid step with `step`
  /// (0: `b < step`, 1: `b == step`, 2: `b > step`).
  function tokensFor(Result memory r, uint8 cmp) internal pure returns (uint256) {
    if (r.kind == KIND_UNDERSUBSCRIBED) return r.fullTokens;
    if (r.kind == KIND_UNCAPPED) return cmp >= 1 ? r.fullTokens : 0;
    if (cmp == 2) return r.fullTokens;
    return cmp == 1 ? r.marginalTokens : 0;
  }
}
