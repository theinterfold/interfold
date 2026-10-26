// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { RoundClearing } from "../libraries/RoundClearing.sol";
import { RoundOutput } from "../libraries/RoundOutput.sol";
import { SlotCodec } from "../libraries/SlotCodec.sol";

/// @notice Unit tests only: exposes the settlement arithmetic, the output decoder and the slot decoder.
contract RoundHarness {
  uint256[16] private prices;
  uint256 public bidderCount;
  mapping(uint256 => address) public bidderAt;
  mapping(address => uint32) public bidCount;

  /// @notice Sets the bidders of the round: bidder `i` is the address `i + 1` and made `counts[i]` bids.
  function setBidders(uint32[] calldata counts) external {
    bidderCount = counts.length;
    for (uint256 i = 0; i < counts.length; i++) {
      address bidder = address(uint160(i + 1));
      bidderAt[i] = bidder;
      bidCount[bidder] = counts[i];
    }
  }

  function decode(
    bytes memory plaintext,
    uint8 levels,
    uint8 reserveStep,
    uint8 lots,
    uint8 minLots
  ) external view returns (uint8 outcome, uint8 step, uint256 counted, uint256 packed) {
    return RoundOutput.decode(plaintext, RoundOutput.Params(levels, reserveStep, lots, minLots), bidderCount, bidderAt, bidCount);
  }

  function usesComplementSide(uint256 theta, uint256 n) external pure returns (bool) {
    return RoundOutput.usesComplementSide(theta, n);
  }

  function setPrices(uint256[16] calldata newPrices) external {
    prices = newPrices;
  }

  function pStar(uint8 outcome, uint8 step, uint8 reserveStep) external view returns (uint256) {
    return RoundClearing.pStar(prices, outcome, step, reserveStep);
  }

  function cost(uint256 tokens, uint256 price, uint256 unit) external pure returns (uint256) {
    return RoundClearing.cost(tokens, price, unit);
  }

  function claimStep(uint8 outcome, uint8 step, uint8 reserveStep) external pure returns (bool needed, uint8 k) {
    return RoundClearing.claimStep(outcome, step, reserveStep);
  }

  function classOf(uint8 outcome, uint8 reserveStep, bool counted, uint8 cmp) external pure returns (uint8) {
    return RoundClearing.classOf(outcome, reserveStep, counted, cmp);
  }

  function marginalFilled(uint8 lots, uint256 aboveClaimed, uint256 rank) external pure returns (bool) {
    return RoundClearing.marginalFilled(lots, aboveClaimed, rank);
  }

  function marginalRank(uint256 mask, uint256 index) external pure returns (uint256) {
    return RoundClearing.marginalRank(mask, index);
  }

  function slots(bytes memory plaintext, uint256 count) external pure returns (uint256[] memory out) {
    uint256[] memory coeffs = SlotCodec.coefficients(plaintext);
    out = new uint256[](count);
    for (uint256 j = 0; j < count; j++) {
      out[j] = SlotCodec.slotAt(coeffs, j);
    }
  }
}
