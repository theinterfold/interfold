// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { RoundClearing } from "./RoundClearing.sol";
import { SlotCodec } from "./SlotCodec.sol";

/// @title Reader of the decrypted output of a private round.
/// @notice The output is one plaintext of 128 slots. The price lane of step `l` has `COPIES` slots
/// `g * 16 + l`, the gate lane has `COPIES` slots from `GATE_BASE`, and the slot `VERSION_BASE + i` is
/// the version of the bid of bidder `i` that was counted (0 if none). A lane slot is zero or uniform
/// random. A lane is zero when all its copies are zero. This library applies every validity rule of
/// `decodeRound` in `sdk/src/layout.ts`: an output that breaks one is `ABORTED`, and does not revert.
/// It is external to keep `PrivateRoundProgram` below the contract size limit.
library RoundOutput {
  uint256 internal constant COPIES = 6;
  uint256 internal constant LEVELS = 16;
  uint256 internal constant GATE_BASE = COPIES * LEVELS;
  uint256 internal constant VERSION_BASE = 115;
  uint256 internal constant MAX_BIDDERS = 13;
  uint256 internal constant MAX_BIDS_PER_BIDDER = 3;

  /// @dev The public parameters of the round that the output is read with.
  struct Params {
    uint8 levels;
    uint8 reserveStep;
    uint8 lots;
    uint8 minLots;
  }

  /// @notice Whether the zero set of the lane test with the threshold `theta` is the complement side
  /// `{theta, ..., n}` for `n` counted bidders (it has fewer zeros than the direct side `{0, ..., theta - 1}`).
  /// With the complement side a zero lane means `c >= theta`; with the direct side it means `c < theta`.
  function usesComplementSide(uint256 theta, uint256 n) internal pure returns (bool) {
    uint256 complement = n + 1 > theta ? n + 1 - theta : 0;
    return complement < theta;
  }

  /// @param plaintext The published plaintext output: 128 little-endian `uint64` coefficients.
  /// @param p The parameters of the round.
  /// @param bidders The number of depositors.
  /// @param bidderAt The depositor of each index of the round.
  /// @param bidCount The bids of each depositor of the round.
  /// @return outcome `NOT_MET`, `UNDERSUBSCRIBED`, `SOLD_OUT` or `ABORTED`.
  /// @return step The last step that sells out for `SOLD_OUT`, the reserve step for `UNDERSUBSCRIBED`, else 0.
  /// @return counted The number of counted bidders (those with a valid counted version).
  /// @return packed The counted version of bidder `i` in bits `2i` and `2i + 1`.
  function decode(
    bytes memory plaintext,
    Params memory p,
    uint256 bidders,
    mapping(uint256 => address) storage bidderAt,
    mapping(address => uint32) storage bidCount
  ) public view returns (uint8 outcome, uint8 step, uint256 counted, uint256 packed) {
    (bool ok, uint256[] memory coeffs) = SlotCodec.tryCoefficients(plaintext);
    if (!ok) return (RoundClearing.ABORTED, 0, 0, 0);

    bool invalid;
    for (uint256 i = 0; i < MAX_BIDDERS; i++) {
      uint256 version = SlotCodec.slotAt(coeffs, VERSION_BASE + i);
      if (version == 0) continue;
      // A version above the bids of the bidder is invalid; so is any version of a bidder that does not exist.
      if (version > MAX_BIDS_PER_BIDDER || i >= bidders || version > bidCount[bidderAt[i]]) {
        invalid = true;
        continue;
      }
      packed |= version << (2 * i);
      counted++;
    }
    if (invalid || counted == 0) return (RoundClearing.ABORTED, 0, counted, packed);

    (outcome, step) = _lanes(coeffs, p, counted);
  }

  /// @dev Reads the price lanes and the gate lane. `counted` is the number of counted bidders.
  function _lanes(uint256[] memory coeffs, Params memory p, uint256 counted) private pure returns (uint8, uint8) {
    // The slots that may hold a lane value: the steps from the reserve to the last, and the gate.
    // Every other slot below the version slots must be zero.
    uint256 nonzeroSteps;
    bool gateNonzero;
    for (uint256 j = 0; j < VERSION_BASE; j++) {
      uint256 value = SlotCodec.slotAt(coeffs, j);
      if (j < GATE_BASE) {
        uint256 level = j % LEVELS;
        if (level >= p.reserveStep && level < p.levels) {
          if (value != 0) nonzeroSteps |= 1 << level;
        } else if (value != 0) {
          return (RoundClearing.ABORTED, 0);
        }
      } else if (j < GATE_BASE + COPIES) {
        if (value != 0) gateNonzero = true;
      } else if (value != 0) {
        return (RoundClearing.ABORTED, 0);
      }
    }

    bool priceComplement = usesComplementSide(p.lots, counted);
    bool gate = (!gateNonzero) == usesComplementSide(p.minLots, counted);
    // `holds` is [c_l >= lots] for the step `l`. It must not rise with the step.
    bool previous;
    uint8 last;
    for (uint256 l = p.reserveStep; l < p.levels; l++) {
      bool holds = ((nonzeroSteps >> l) & 1 == 0) == priceComplement;
      if (holds) {
        if (l > p.reserveStep && !previous) return (RoundClearing.ABORTED, 0);
        last = uint8(l);
      }
      previous = holds;
    }
    bool soldOutAtReserve = ((nonzeroSteps >> p.reserveStep) & 1 == 0) == priceComplement;
    // The sell-out at the reserve step needs the gate.
    if (soldOutAtReserve && !gate) return (RoundClearing.ABORTED, 0);

    if (!gate) return (RoundClearing.NOT_MET, 0);
    if (!soldOutAtReserve) return (RoundClearing.UNDERSUBSCRIBED, p.reserveStep);
    return (RoundClearing.SOLD_OUT, last);
  }
}
