// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { SlotCodec } from "./SlotCodec.sol";

/// @title Reader of the decrypted output of one round of a sale.
/// @notice The output is `sum(ciphertexts) * keepMask`, one plaintext of 128 slots. The cell `(l, j)` is the slot
/// `6 l + j`: the digit `j` (base 4, little endian) of the budgets of the counted bids with step `>= l`, for the
/// levels `l` of the probe mask of the round. The slot `96 + c` holds the counted flags `2^(i % 8)` of the bids
/// `8 c` to `8 c + 7`. The budget sum of a level is `F[l] = sum_j 4^j cell(l, j)`. This library is external to keep
/// `TokenLaunchProgram` below the contract size limit.
library SaleOutput {
  uint256 internal constant LANES = 6;
  uint256 internal constant FLAG_BASE = 96;
  uint256 internal constant FLAG_CELLS = 11;
  /// @dev The largest budget of a bid, in budget units.
  uint256 internal constant MAX_BUDGET_UNITS = 4095;

  /// @param plaintext The published plaintext output: 128 little-endian `uint64` coefficients.
  /// @param probeMask Bit `l` is set when the cells of level `l` are revealed.
  /// @param bids The number of bids of the sale.
  /// @return valid False for an output that an honest committee and program cannot produce: the wrong length, a
  /// coefficient of 257 or more, a cell above `3 * bids`, a flag cell above 255, a flag of a bid that does not
  /// exist, or a sum above `4095 * counted bids`.
  /// @return sums `F[l]` in budget units for the levels of `probeMask`, 0 elsewhere.
  /// @return counted Bit `i` is set when the bid `i` was counted.
  function decode(
    bytes memory plaintext,
    uint16 probeMask,
    uint256 bids
  ) public pure returns (bool valid, uint256[16] memory sums, uint256 counted) {
    if (plaintext.length != SlotCodec.OUTPUT_BYTES) return (false, sums, 0);
    (uint256[] memory coeffs, uint256 bad) = SlotCodec.scan(plaintext);
    if (bad != SlotCodec.DEGREE) return (false, sums, 0);

    for (uint256 c = 0; c < FLAG_CELLS; c++) {
      uint256 flags = SlotCodec.slotAt(coeffs, FLAG_BASE + c);
      // A cell is a sum of distinct powers of two below 2^8, so it is at most 255 (the slot value is below 257).
      if (flags > 255) return (false, sums, 0);
      counted |= flags << (8 * c);
    }
    if (counted >> bids != 0) return (false, sums, 0);
    uint256 countedBids;
    for (uint256 i = 0; i < bids; i++) countedBids += (counted >> i) & 1;

    for (uint256 l = 0; l < 16; l++) {
      if (probeMask & (1 << l) == 0) continue;
      uint256 sum;
      for (uint256 j = 0; j < LANES; j++) {
        uint256 cell = SlotCodec.slotAt(coeffs, LANES * l + j);
        if (cell > 3 * bids) return (false, sums, 0);
        sum += cell << (2 * j);
      }
      if (sum > MAX_BUDGET_UNITS * countedBids) return (false, sums, 0);
      sums[l] = sum;
    }
    valid = true;
  }
}
