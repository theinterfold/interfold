// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IBidVerifier } from "../interfaces/IBidVerifier.sol";
import { ITokenLaunch } from "../interfaces/ITokenLaunch.sol";
import { ClaimContext, ProofInputs } from "./ProofInputs.sol";
import { SaleClearing } from "./SaleClearing.sol";
import { Sale } from "./SaleConfig.sol";
import { Accounts, Bid, Cleared, Marginal, Progress, SaleState } from "./SaleState.sol";

/// @title Everything that moves funds of a cleared, failed or aborted sale.
/// @notice An external library of `TokenLaunchProgram` (contract size limit): its functions run in the program's
/// context on the storage of one sale. The program checks which phase a call needs; this library checks the data.
///
/// Claims. A claim proves a bid is in the claim tree and how it compares with the clearing step. It pays at once,
/// except one case: in a capped sale the bids at the clearing step share `R` tokens first bid first, so their order
/// matters. Inside the marginal window such a claim only registers (the proof publishes the bid index, the budget and
/// the recipient), and `payMarginal` pays it after the window from the fills of the registered claims. A marginal claim
/// after the window gets its refund only.
library Settlement {
  using SafeERC20 for IERC20;

  // ---------------------------------------------------------------------------------------------
  // Claims
  // ---------------------------------------------------------------------------------------------

  /// @notice Pay or register a claim: `data = abi.encode(ClaimData)`.
  function claim(SaleState storage st, uint256 saleId, bytes calldata data, address verifier) public {
    ITokenLaunch.ClaimData memory c = abi.decode(data, (ITokenLaunch.ClaimData));
    Progress storage p = st.progress;
    if (!p.cleared) revert ITokenLaunch.NotCleared();
    if (block.timestamp > p.claimDeadline) revert ITokenLaunch.ClaimWindowClosed(p.claimDeadline);
    if (st.nullifiers[c.nullifier]) revert ITokenLaunch.NullifierUsed(c.nullifier);
    _checkClaimData(st.sale, c);
    Cleared storage out = st.cleared;
    bool reveal = out.kind == SaleClearing.KIND_CAPPED && block.timestamp <= p.marginalDeadline;
    bool register = reveal && c.cmp == 1;
    // Only a registration publishes an index, and it must be the index of a bid.
    if (register ? (c.indexPlusOne == 0 || c.indexPlusOne > p.bidCount) : c.indexPlusOne != 0) revert ITokenLaunch.InvalidClaim();
    ProofInputs.verifyClaim(verifier, c, ClaimContext(saleId, out.root, out.countedMask, out.step, reveal));
    st.nullifiers[c.nullifier] = true;

    if (register) {
      Marginal storage m = st.marginals[c.indexPlusOne - 1];
      if (m.registered) revert ITokenLaunch.AlreadyRegistered(c.indexPlusOne - 1);
      m.registered = true;
      m.recipient = c.recipient;
      m.budgetUnits = c.budgetUnits;
      m.escrowUnits = c.escrowUnits;
      emit ITokenLaunch.MarginalRegistered(saleId, c.indexPlusOne - 1, c.budgetUnits, c.recipient);
      return;
    }
    (uint256 tokens, uint256 paid, uint256 refund) = _immediate(st, c.cmp, c.budgetUnits, c.escrowUnits);
    _pay(st, c.recipient, c.escrowUnits, tokens, paid, refund);
    emit ITokenLaunch.Claimed(saleId, c.nullifier, c.recipient, tokens, paid, refund);
  }

  /// @dev What the circuit leaves to the contract: the tier is one of the sale, and the claim values agree.
  function _checkClaimData(Sale storage s, ITokenLaunch.ClaimData memory c) private view {
    if (c.cmp > 2 || c.budgetUnits > c.escrowUnits || (c.cmp == 0) != (c.budgetUnits == 0)) revert ITokenLaunch.InvalidClaim();
    uint16[4] storage tiers = s.tiers;
    if (
      c.escrowUnits == 0 ||
      (c.escrowUnits != tiers[0] && c.escrowUnits != tiers[1] && c.escrowUnits != tiers[2] && c.escrowUnits != tiers[3])
    ) {
      revert ITokenLaunch.InvalidClaim();
    }
  }

  function _result(SaleState storage st) private view returns (SaleClearing.Result memory) {
    Cleared storage out = st.cleared;
    return SaleClearing.Result(out.kind, out.step, out.pStar, out.sold, out.remaining);
  }

  /// @dev The payout of a claim that does not wait for the marginal fills.
  function _immediate(
    SaleState storage st,
    uint8 cmp,
    uint16 budgetUnits,
    uint16 escrowUnits
  ) private view returns (uint256 tokens, uint256 paid, uint256 refund) {
    Sale storage s = st.sale;
    tokens = SaleClearing.tokensFor(_result(st), cmp, uint256(budgetUnits) * s.budgetUnit, s.saleUnit);
    paid = SaleClearing.cost(tokens, st.cleared.pStar, s.saleUnit);
    refund = uint256(escrowUnits) * s.budgetUnit - paid;
  }

  /// @notice What a claim pays for `cmp`, `budgetUnits` and `escrowUnits`.
  function previewClaim(
    SaleState storage st,
    uint8 cmp,
    uint16 budgetUnits,
    uint16 escrowUnits
  ) public view returns (uint256 tokens, uint256 paid, uint256 refund) {
    if (!st.progress.cleared) revert ITokenLaunch.NotCleared();
    if (cmp > 2) revert ITokenLaunch.InvalidClaim();
    return _immediate(st, cmp, budgetUnits, escrowUnits);
  }

  /// @dev Books a payout and sends it to `recipient`.
  function _pay(SaleState storage st, address recipient, uint16 escrowUnits, uint256 tokens, uint256 paid, uint256 refund) private {
    Sale storage s = st.sale;
    Accounts storage a = st.accounts;
    a.escrowClaimed += uint256(escrowUnits) * s.budgetUnit;
    a.proceeds += paid;
    a.tokensClaimed += tokens;
    if (tokens != 0) IERC20(s.saleToken).safeTransfer(recipient, tokens);
    if (refund != 0) IERC20(s.paymentToken).safeTransfer(recipient, refund);
  }

  // ---------------------------------------------------------------------------------------------
  // Marginal claims
  // ---------------------------------------------------------------------------------------------

  /// @notice The payout of the registered marginal claim of bid `index`: ascending bid index over the registered claims,
  /// each gets `min(full fill, what is left of R)`. All 0 when the bid did not register.
  function marginalAmounts(SaleState storage st, uint256 index) public view returns (uint256 tokens, uint256 paid, uint256 refund) {
    Marginal storage own = st.marginals[index];
    if (!own.registered) return (0, 0, 0);
    Sale storage s = st.sale;
    uint256 pStar = st.cleared.pStar;
    uint256 left = st.cleared.remaining;
    for (uint256 i = 0; i < index; i++) {
      Marginal storage m = st.marginals[i];
      if (!m.registered) continue;
      uint256 fill = SaleClearing.fullFill(uint256(m.budgetUnits) * s.budgetUnit, pStar, s.saleUnit);
      left -= fill < left ? fill : left;
    }
    tokens = SaleClearing.fullFill(uint256(own.budgetUnits) * s.budgetUnit, pStar, s.saleUnit);
    if (left < tokens) tokens = left;
    paid = SaleClearing.cost(tokens, pStar, s.saleUnit);
    refund = uint256(own.escrowUnits) * s.budgetUnit - paid;
  }

  /// @notice Pay the registered marginal claim of bid `index`, once, after the marginal window.
  function payMarginal(SaleState storage st, uint256 saleId, uint256 index) public {
    Progress storage p = st.progress;
    if (!p.cleared) revert ITokenLaunch.NotCleared();
    if (block.timestamp <= p.marginalDeadline) revert ITokenLaunch.MarginalWindowOpen(p.marginalDeadline);
    if (block.timestamp > p.claimDeadline) revert ITokenLaunch.ClaimWindowClosed(p.claimDeadline);
    Marginal storage m = st.marginals[index];
    if (!m.registered) revert ITokenLaunch.NotRegistered(index);
    if (m.paid) revert ITokenLaunch.AlreadyPaid(index);
    m.paid = true;
    (uint256 tokens, uint256 paid, uint256 refund) = marginalAmounts(st, index);
    _pay(st, m.recipient, m.escrowUnits, tokens, paid, refund);
    emit ITokenLaunch.MarginalPaid(saleId, index, m.recipient, tokens, paid, refund);
  }

  // ---------------------------------------------------------------------------------------------
  // Refunds
  // ---------------------------------------------------------------------------------------------

  /// @notice After `clear`: the escrow of a bid that was not counted goes back to its bidder.
  function refundDropped(SaleState storage st, uint256 saleId, uint256 index) public {
    if (!st.progress.cleared) revert ITokenLaunch.NotCleared();
    if (index >= st.progress.bidCount) revert ITokenLaunch.InvalidBidIndex(index);
    if ((st.cleared.countedMask >> index) & 1 != 0) revert ITokenLaunch.NotDropped(index);
    uint256 amount = _refundBid(st, index);
    emit ITokenLaunch.DroppedRefunded(saleId, index, st.bids[index].bidder, amount);
  }

  /// @notice A failed or aborted sale: the escrow of a bid goes back to its bidder, unless it is forfeited. The
  /// program checks the phase.
  function refundEscrow(SaleState storage st, uint256 saleId, uint256 index) public {
    if (index >= st.progress.bidCount) revert ITokenLaunch.InvalidBidIndex(index);
    if ((st.forfeitMask >> index) & 1 != 0) revert ITokenLaunch.Forfeited(index);
    uint256 amount = _refundBid(st, index);
    emit ITokenLaunch.EscrowRefunded(saleId, index, st.bids[index].bidder, amount);
  }

  function _refundBid(SaleState storage st, uint256 index) private returns (uint256 amount) {
    Bid storage bid = st.bids[index];
    if (bid.refunded) revert ITokenLaunch.AlreadyRefunded(index);
    bid.refunded = true;
    amount = uint256(st.sale.tiers[bid.tier]) * st.sale.budgetUnit;
    IERC20(st.sale.paymentToken).safeTransfer(bid.bidder, amount);
  }

  // ---------------------------------------------------------------------------------------------
  // Creator
  // ---------------------------------------------------------------------------------------------

  function _onlyCreator(Sale storage s) private view {
    if (msg.sender != s.creator) revert ITokenLaunch.NotCreator(msg.sender);
  }

  function withdrawProceeds(SaleState storage st, uint256 saleId) public {
    Sale storage s = st.sale;
    _onlyCreator(s);
    uint256 amount = st.accounts.proceeds;
    if (amount == 0) revert ITokenLaunch.NothingToWithdraw();
    st.accounts.proceeds = 0;
    IERC20(s.paymentToken).safeTransfer(s.creator, amount);
    emit ITokenLaunch.ProceedsWithdrawn(saleId, s.creator, amount);
  }

  /// @notice The sale tokens that the clearing does not sell, once.
  function withdrawUnsold(SaleState storage st, uint256 saleId) public {
    Sale storage s = st.sale;
    _onlyCreator(s);
    Progress storage p = st.progress;
    if (!p.cleared) revert ITokenLaunch.NotCleared();
    if (p.unsoldWithdrawn) revert ITokenLaunch.NothingToWithdraw();
    uint256 amount = s.supply - st.cleared.sold;
    if (amount == 0) revert ITokenLaunch.NothingToWithdraw();
    p.unsoldWithdrawn = true;
    IERC20(s.saleToken).safeTransfer(s.creator, amount);
    emit ITokenLaunch.UnsoldWithdrawn(saleId, s.creator, amount);
  }

  /// @notice After the claim window the creator takes everything that is still held for the sale: the supply that
  /// claimants did not take and the creator did not take as unsold (this includes the marginal tokens that nobody
  /// registered for), the escrows of counted bids that did not claim, and the payments not taken yet. It moves only
  /// the amounts of this sale, which the program counts per sale. The escrows of dropped bids stay for their bidders.
  function sweep(SaleState storage st, uint256 saleId) public {
    Sale storage s = st.sale;
    _onlyCreator(s);
    Progress storage p = st.progress;
    if (!p.cleared) revert ITokenLaunch.NotCleared();
    if (block.timestamp <= p.claimDeadline) revert ITokenLaunch.ClaimWindowOpen(p.claimDeadline);
    if (p.swept) revert ITokenLaunch.AlreadySwept();
    p.swept = true;
    Accounts storage a = st.accounts;
    uint256 saleTokens = s.supply - a.tokensClaimed - (p.unsoldWithdrawn ? s.supply - st.cleared.sold : 0);
    uint256 paymentTokens = a.escrowTotal - a.droppedEscrow - a.escrowClaimed + a.proceeds;
    p.unsoldWithdrawn = true;
    a.proceeds = 0;
    if (saleTokens != 0) IERC20(s.saleToken).safeTransfer(s.creator, saleTokens);
    if (paymentTokens != 0) IERC20(s.paymentToken).safeTransfer(s.creator, paymentTokens);
    emit ITokenLaunch.Swept(saleId, s.creator, saleTokens, paymentTokens);
  }

  /// @notice A failed or aborted sale: the creator takes the supply back, once. The program checks the phase.
  function refundSupply(SaleState storage st, uint256 saleId) public {
    Sale storage s = st.sale;
    _onlyCreator(s);
    if (st.progress.supplyRefunded) revert ITokenLaunch.NothingToWithdraw();
    st.progress.supplyRefunded = true;
    IERC20(s.saleToken).safeTransfer(s.creator, s.supply);
    emit ITokenLaunch.SupplyRefunded(saleId, s.creator, s.supply);
  }

  /// @notice A sale that aborted on a counted-set mismatch: the creator takes the forfeited escrows, once.
  function withdrawForfeited(SaleState storage st, uint256 saleId) public {
    Sale storage s = st.sale;
    _onlyCreator(s);
    Progress storage p = st.progress;
    uint256 amount = st.accounts.forfeitedEscrow;
    if (p.abortReason != ITokenLaunch.AbortReason.CountedSetMismatch || p.forfeitedWithdrawn || amount == 0) {
      revert ITokenLaunch.NothingToWithdraw();
    }
    p.forfeitedWithdrawn = true;
    IERC20(s.paymentToken).safeTransfer(s.creator, amount);
    emit ITokenLaunch.ForfeitedWithdrawn(saleId, s.creator, amount);
  }
}
