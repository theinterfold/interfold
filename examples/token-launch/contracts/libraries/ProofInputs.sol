// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IBidVerifier } from "../interfaces/IBidVerifier.sol";
import { ITokenLaunch } from "../interfaces/ITokenLaunch.sol";

/// @notice What the pair bid proof binds besides the bid itself.
struct BidContext {
  uint256 saleId;
  uint256 index;
  uint8 levels;
  uint16 escrowUnits;
  /// @dev The committee key commitments of round 1 and round 2.
  bytes32 key1;
  bytes32 key2;
  bytes32 vkAnchor;
}

/// @notice What the claim proof binds besides the claim itself: the clearing of the sale.
struct ClaimContext {
  uint256 saleId;
  uint256 root;
  uint256 countedMask;
  uint8 step;
  /// @dev 1 when a marginal claim may reveal its bid index: capped sale inside the marginal window.
  bool reveal;
}

/// @title The public inputs of the bid and the claim proofs.
/// @notice External, to keep the array building out of `TokenLaunchProgram` (contract size limit). The order of the
/// inputs is the order of the circuits' public inputs (`circuits/PUBLIC_INPUTS.md`).
library ProofInputs {
  /// @dev The BN254 scalar field modulus. An E3 id can exceed it, so the circuits get `saleId mod r`.
  uint256 private constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// @dev `ct_commitment_1, ct_commitment_2, bid_commitment, bidder, sale_id, levels, bidder_index, escrow_units,
  /// pk_commitment_1, pk_commitment_2, vk_anchor`.
  function verifyBid(address verifier, ITokenLaunch.BidInput memory bid, BidContext memory c) public view {
    bytes32[] memory publicInputs = new bytes32[](11);
    publicInputs[0] = bid.ctCommitment1;
    publicInputs[1] = bid.ctCommitment2;
    publicInputs[2] = bid.bidCommitment;
    publicInputs[3] = bytes32(uint256(uint160(bid.bidder)));
    publicInputs[4] = bytes32(c.saleId % FIELD);
    publicInputs[5] = bytes32(uint256(c.levels));
    publicInputs[6] = bytes32(c.index);
    publicInputs[7] = bytes32(uint256(c.escrowUnits));
    publicInputs[8] = c.key1;
    publicInputs[9] = c.key2;
    publicInputs[10] = c.vkAnchor;
    if (!IBidVerifier(verifier).verify(bid.proof, publicInputs)) revert ITokenLaunch.InvalidBidProof();
  }

  /// @dev `root, counted_mask, sale_id, k, nullifier, recipient, escrow_units, budget_units, reveal_index, cmp,
  /// index_plus_one`.
  function verifyClaim(address verifier, ITokenLaunch.ClaimData memory claim, ClaimContext memory c) public view {
    bytes32[] memory publicInputs = new bytes32[](11);
    publicInputs[0] = bytes32(c.root);
    publicInputs[1] = bytes32(c.countedMask);
    publicInputs[2] = bytes32(c.saleId % FIELD);
    publicInputs[3] = bytes32(uint256(c.step));
    publicInputs[4] = claim.nullifier;
    publicInputs[5] = bytes32(uint256(uint160(claim.recipient)));
    publicInputs[6] = bytes32(uint256(claim.escrowUnits));
    publicInputs[7] = bytes32(uint256(claim.budgetUnits));
    publicInputs[8] = c.reveal ? bytes32(uint256(1)) : bytes32(0);
    publicInputs[9] = bytes32(uint256(claim.cmp));
    publicInputs[10] = bytes32(uint256(claim.indexPlusOne));
    if (!IBidVerifier(verifier).verify(claim.proof, publicInputs)) revert ITokenLaunch.InvalidClaimProof();
  }
}
