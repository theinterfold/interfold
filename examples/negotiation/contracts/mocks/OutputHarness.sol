// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { NegotiationOutput } from "../libraries/NegotiationOutput.sol";
import { SlotCodec } from "../libraries/SlotCodec.sol";

/// @notice Unit tests only. It exposes `NegotiationOutput` with the reference sums of `SlotCodec`: the
/// 8 slots of each level, one by one.
contract OutputHarness {
  function levelSums(bytes calldata plaintext) external pure returns (uint256[16] memory) {
    return NegotiationOutput.levelSums(plaintext);
  }

  function referenceSums(bytes calldata plaintext) external pure returns (uint256[16] memory sums) {
    uint256[] memory coeffs = SlotCodec.coefficients(plaintext);
    for (uint256 i = 0; i < 16; i++) {
      uint256 acc;
      for (uint256 g = 0; g < 8; g++) acc += SlotCodec.slotAt(coeffs, g * 16 + i);
      sums[i] = acc % 257;
    }
  }

  function decode(bytes calldata plaintext, uint8 levels) external pure returns (bool matched, uint8 step) {
    return NegotiationOutput.decode(plaintext, levels);
  }
}
