// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { SlotCodec } from "./SlotCodec.sol";

/// @title Reader of the decrypted output of a sale (reveal mode 0).
/// @notice The output is one plaintext of 128 slots: the slots 0 to 15 are the demand curve `c[l]`,
/// and the slot `16 + i` is the version of the bid of bidder `i` that was counted, 0 if none. This
/// library is external to keep `SealedCcaProgram` below the contract size limit.
library SaleOutput {
  uint256 internal constant CURVE_SLOTS = 16;
  uint256 internal constant COUNTED_SLOT_OFFSET = 16;

  error InvalidOutput();

  /// @param plaintext The published plaintext output: 128 little-endian `uint64` coefficients.
  /// @param levels The number of price steps of the sale.
  /// @param bidders The number of depositors.
  /// @param bidderAt The depositor of each index of the sale.
  /// @param bidCount The bids of each depositor of the sale.
  /// @return c The demand curve. It must not increase with the step, it is empty from `levels`, and
  /// it counts at most the depositors.
  /// @return packed The counted version of bidder `i` in bits `2i` and `2i + 1`. A version is at
  /// most the bids of the bidder. The number of counted bidders is `c[0]`, because every bid has the
  /// thermometer slot 0 set.
  function decode(
    bytes memory plaintext,
    uint8 levels,
    uint256 bidders,
    mapping(uint256 => address) storage bidderAt,
    mapping(address => uint32) storage bidCount
  ) public view returns (uint256[16] memory c, uint256 packed) {
    uint256[] memory coeffs = SlotCodec.coefficients(plaintext);
    for (uint256 l = 0; l < CURVE_SLOTS; l++) {
      c[l] = SlotCodec.slotAt(coeffs, l);
      if (c[l] > bidders || (l > 0 && c[l] > c[l - 1]) || (l >= levels && c[l] != 0)) revert InvalidOutput();
    }
    uint256 counted;
    for (uint256 i = 0; i < bidders; i++) {
      uint256 version = SlotCodec.slotAt(coeffs, COUNTED_SLOT_OFFSET + i);
      if (version == 0) continue;
      if (version > bidCount[bidderAt[i]]) revert InvalidOutput();
      packed |= version << (2 * i);
      counted++;
    }
    if (counted != c[0]) revert InvalidOutput();
  }
}
