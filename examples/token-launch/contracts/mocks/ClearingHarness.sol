// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IBidVerifier } from "../interfaces/IBidVerifier.sol";
import { ITokenLaunch } from "../interfaces/ITokenLaunch.sol";
import { BidContext, ClaimContext, ProofInputs } from "../libraries/ProofInputs.sol";
import { Grid, ProbeSearch } from "../libraries/ProbeSearch.sol";
import { SaleClearing } from "../libraries/SaleClearing.sol";
import { SaleOutput } from "../libraries/SaleOutput.sol";
import { SlotCodec } from "../libraries/SlotCodec.sol";

/// @notice Unit tests only: exposes the probe search, the clearing math, the output reader, the slot decoder and the
/// public inputs of the proofs.
contract ClearingHarness {
  function coarseProbeMask(uint8 levels) external pure returns (uint16) {
    return ProbeSearch.coarseProbeMask(levels);
  }

  function round1(Grid memory g, uint256[16] memory sums) external pure returns (bool valid, uint8 lo, uint8 hi, uint16 mask2) {
    return ProbeSearch.round1(g, sums, ProbeSearch.coarseProbeMask(g.levels));
  }

  function round2(
    Grid memory g,
    uint256[16] memory sums1,
    uint256[16] memory sums2,
    uint8 lo,
    uint16 mask2
  ) external pure returns (bool valid, uint8 lstar, uint256[16] memory merged) {
    return ProbeSearch.round2(g, sums1, sums2, ProbeSearch.coarseProbeMask(g.levels), lo, mask2);
  }

  function clear(Grid memory g, uint8 lstar, uint256[16] memory sums) external pure returns (SaleClearing.Result memory) {
    return SaleClearing.clear(g, lstar, sums);
  }

  /// @notice Tokens, payment and refund of a claim with the comparison `cmp`.
  function outcome(
    SaleClearing.Result memory r,
    uint8 cmp,
    uint256 budgetUnits,
    uint256 escrowUnits,
    uint256 budgetUnit,
    uint256 saleUnit
  ) external pure returns (uint256 tokens, uint256 paid, uint256 refund) {
    tokens = SaleClearing.tokensFor(r, cmp, budgetUnits * budgetUnit, saleUnit);
    paid = SaleClearing.cost(tokens, r.pStar, saleUnit);
    refund = escrowUnits * budgetUnit - paid;
  }

  function decodeOutput(
    bytes memory plaintext,
    uint16 probeMask,
    uint256 bids
  ) external pure returns (bool valid, uint256[16] memory sums, uint256 counted) {
    return SaleOutput.decode(plaintext, probeMask, bids);
  }

  function slots(bytes memory plaintext, uint256 count) external pure returns (uint256[] memory out) {
    uint256[] memory coeffs = SlotCodec.coefficients(plaintext);
    out = new uint256[](count);
    for (uint256 j = 0; j < count; j++) {
      out[j] = SlotCodec.slotAt(coeffs, j);
    }
  }

  /// @notice Runs the verifier with the public inputs that the program builds for a bid.
  function verifyBid(address bidVerifier, ITokenLaunch.BidInput memory bid, BidContext memory c) external view {
    ProofInputs.verifyBid(bidVerifier, bid, c);
  }

  /// @notice Runs the verifier with the public inputs that the program builds for a claim.
  function verifyClaim(address claimVerifier, ITokenLaunch.ClaimData memory data, ClaimContext memory c) external view {
    ProofInputs.verifyClaim(claimVerifier, data, c);
  }
}
