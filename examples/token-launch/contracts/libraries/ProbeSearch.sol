// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice The price grid and the sizes of a sale, as the probe search and the clearing read them.
struct Grid {
  /// @dev The price of each step; only the first `levels` are read.
  uint256[16] prices;
  uint8 levels;
  /// @dev `S`, the sale-token base units to sell.
  uint256 supply;
  /// @dev Payment-token base units of one budget unit.
  uint256 budgetUnit;
  /// @dev `U = 10^saleDecimals`.
  uint256 saleUnit;
}

/// @title The two-round probe search for the clearing step of a sale.
/// @notice `F[l]` is the budget sum (budget units) of the bids with step `>= l`. The committee reveals `F` at a few
/// probe levels only. Round 1 reveals `F` at the coarse levels `P1`, which brackets the clearing step in `(lo, hi)`;
/// round 2 reveals `F` at the levels strictly inside the bracket (`P2`, plus level 0 if `lo == 0`) and
/// fixes the clearing step `lstar`. `sdk/src/probes.ts` mirrors this file, and the vectors
/// `sdk/test-vectors/clearing.json` pin them together.
///
/// `over(m)` is the over-demand test `F[m] * unit * U > p[m-1] * S`, for `m` in `1..levels`. A valid output is
/// monotone: `over(m)` is true for `m <= lstar` and false after. `over(0)` is true and `over(levels)` is false.
library ProbeSearch {
  /// @notice Level `m` is a probe of round 1 when `m` is a multiple of `ceil(levels / 4)` in `1..levels-1`.
  function coarseProbeMask(uint8 levels) public pure returns (uint16 mask) {
    uint256 g = (uint256(levels) + 3) / 4;
    for (uint256 m = g; m < levels; m += g) mask |= uint16(1 << m);
  }

  /// @notice Round 1.
  /// @param sums `F[m]` for the levels of `mask1`; the other entries are ignored.
  /// @return valid False when the sums are not a monotone demand curve (non-monotone `F`, or `over` not a prefix).
  /// @return lo The highest probe with over-demand, 0 if none.
  /// @return hi The lowest probe above `lo`, `levels` if none.
  /// @return mask2 The levels of round 2: `lo < m < hi`, and 0 when `lo == 0`.
  function round1(Grid memory g, uint256[16] memory sums, uint16 mask1) public pure returns (bool valid, uint8 lo, uint8 hi, uint16 mask2) {
    uint256 previous = type(uint256).max;
    for (uint256 m = 1; m < g.levels; m++) {
      if (mask1 & (1 << m) == 0) continue;
      if (sums[m] > previous) return (false, 0, 0, 0);
      previous = sums[m];
      if (over(g, m, sums[m])) lo = uint8(m);
    }
    hi = g.levels;
    for (uint256 m = 1; m < g.levels; m++) {
      if (mask1 & (1 << m) == 0) continue;
      // `over` must be true up to `lo` and false above it.
      if (over(g, m, sums[m]) != (m <= lo)) return (false, 0, 0, 0);
      if (m > lo && m < hi) hi = uint8(m);
    }
    for (uint256 m = uint256(lo) + 1; m < hi; m++) mask2 |= uint16(1 << m);
    if (lo == 0) mask2 |= 1;
    valid = true;
  }

  /// @notice Round 2.
  /// @param sums1 `F` at the levels of `mask1` (round 1).
  /// @param sums2 `F` at the levels of `mask2` (round 2); the other entries are ignored.
  /// @return valid False when the merged sums are not non-increasing over the known levels, or `over` is not a
  /// prefix over the levels of `mask2`.
  /// @return lstar The clearing step: the highest level with over-demand, at least `lo`.
  /// @return merged `F` at the known levels (`mask1 | mask2`), 0 elsewhere.
  function round2(
    Grid memory g,
    uint256[16] memory sums1,
    uint256[16] memory sums2,
    uint16 mask1,
    uint8 lo,
    uint16 mask2
  ) public pure returns (bool valid, uint8 lstar, uint256[16] memory merged) {
    uint256 previous = type(uint256).max;
    lstar = lo;
    for (uint256 m = 0; m < g.levels; m++) {
      if (mask1 & (1 << m) != 0) merged[m] = sums1[m];
      else if (mask2 & (1 << m) != 0) merged[m] = sums2[m];
      else continue;
      if (merged[m] > previous) return (false, 0, merged);
      previous = merged[m];
      if (m > 0 && mask2 & (1 << m) != 0 && over(g, m, merged[m])) lstar = uint8(m);
    }
    for (uint256 m = 1; m < g.levels; m++) {
      if (mask2 & (1 << m) == 0) continue;
      if (over(g, m, merged[m]) != (m <= lstar)) return (false, 0, merged);
    }
    valid = true;
  }

  /// @notice The over-demand test at level `m >= 1` for the budget sum `f` (budget units).
  function over(Grid memory g, uint256 m, uint256 f) internal pure returns (bool) {
    return f * g.budgetUnit * g.saleUnit > g.prices[m - 1] * g.supply;
  }
}
