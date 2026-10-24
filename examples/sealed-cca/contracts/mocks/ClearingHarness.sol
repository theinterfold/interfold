// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { SaleClearing } from "../libraries/SaleClearing.sol";
import { SlotCodec } from "../libraries/SlotCodec.sol";

/// @notice Unit tests only: exposes the clearing math and the slot decoder.
contract ClearingHarness {
  function clear(
    uint256[16] memory prices,
    uint8 levels,
    uint256[16] memory c,
    uint256 supply,
    uint256 escrow,
    uint256 unit
  ) external pure returns (SaleClearing.Result memory) {
    return SaleClearing.clear(prices, levels, c, supply, escrow, unit);
  }

  /// @notice Tokens and payment of a bidder with the comparison `cmp`.
  function outcome(
    SaleClearing.Result memory r,
    uint8 cmp,
    uint256 escrow,
    uint256 unit
  ) external pure returns (uint256 tokens, uint256 paid, uint256 refund) {
    tokens = SaleClearing.tokensFor(r, cmp);
    paid = SaleClearing.cost(tokens, r.pStar, unit);
    refund = escrow - paid;
  }

  function slots(bytes memory plaintext, uint256 count) external pure returns (uint256[] memory out) {
    uint256[] memory coeffs = SlotCodec.coefficients(plaintext);
    out = new uint256[](count);
    for (uint256 j = 0; j < count; j++) {
      out[j] = SlotCodec.slotAt(coeffs, j);
    }
  }
}
