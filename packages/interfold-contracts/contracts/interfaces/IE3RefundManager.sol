// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;
import { IInterfold } from "./IInterfold.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IE3RefundManager
 * @notice Interface for E3 refund distribution mechanism
 * @dev Handles refund calculation and claiming for failed E3s
 */
interface IE3RefundManager {
    /// @notice The E3 request does not have a configured slashing manager.
    error InvalidSlashingManager();

    /// @notice A settlement transfer delivered a different amount than requested.
    error AssetTransferMismatch(IERC20 token, uint256 expected, uint256 actual);

    /// @notice Settlement is blocked until the accusation window closes and every
    ///         committee-affecting proposal resolves, or until the hard cutoff.
    /// @dev Bare, for size. Read `ISlashingManager.settlementOpen`,
    ///      `accusationSubmissionDeadline` and `settlementCutoff` to see why.
    error SettlementBlocked();

    /// @notice Identifies which collateral pool bears a failed E3's completed-work cost.
    enum FailurePayer {
        None,
        Requester,
        Ciphernodes
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                        Structs                         //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice Work value allocation in basis points (10000 = 100%)
    struct WorkValueAllocation {
        uint16 committeeFormationBps;
        uint16 dkgBps;
        uint16 decryptionBps;
        uint16 protocolBps;
        uint16 successSlashedNodeBps;
    }
    /// @notice Immutable settlement policy selected when an E3 is requested.
    struct E3PolicySnapshot {
        WorkValueAllocation allocation;
        address treasury;
        address interfold;
        address registry;
        uint64 version;
        bool initialized;
        address bondingRegistry;
        address slashingManager;
    }
    /// @notice Refund distribution for a failed E3
    struct RefundDistribution {
        uint256 requesterAmount; // Amount for requester
        uint256 honestNodeAmount; // Total amount for honest nodes
        uint256 protocolAmount; // Amount for protocol treasury
        uint256 totalSlashed; // Cumulative settled slashes denominated in the E3 fee token
        uint256 honestNodeCount; // Number of honest nodes
        bool calculated; // Whether distribution is calculated
        IERC20 feeToken; // The fee token used for this E3's payment (stored per-E3 to survive token rotations)
        uint256 originalPayment; // Original E3 payment amount retained for settlement auditability
        uint256 perNodeAmount; // Snapshotted per-honest-node payout; 0 when honestNodeCount==0
    }
    ////////////////////////////////////////////////////////////
    //                                                        //
    //                        Events                          //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice Emitted when refund distribution is calculated
    event RefundDistributionCalculated(
        uint256 indexed e3Id,
        uint256 requesterAmount,
        uint256 honestNodeAmount,
        uint256 protocolAmount,
        uint256 totalSlashed
    );
    /// @notice Emitted when a refund is claimed
    event RefundClaimed(
        uint256 indexed e3Id,
        address indexed claimant,
        uint256 amount,
        bytes32 claimType
    );
    /// @notice Emitted when slashed funds are escrowed for an E3
    event SlashedFundsEscrowed(
        uint256 indexed e3Id,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when slashed funds are applied to a failed E3's refund distribution
    event SlashedFundsApplied(
        uint256 indexed e3Id,
        IERC20 indexed token,
        uint256 toRequester,
        uint256 toHonestNodes
    );
    /// @notice Emitted when escrowed slashed funds are distributed on success
    /// @dev Both `toNodes` and `toProtocol` are credited (pull-payment) — see
    ///      `SlashedFundsCredited` / `TreasurySlashedCredited` for per-recipient detail.
    event SlashedFundsDistributedOnSuccess(
        uint256 indexed e3Id,
        IERC20 indexed token,
        uint256 toNodes,
        uint256 toProtocol
    );
    /// @notice Emitted when an honest node is credited slashed funds (success path).
    event SlashedFundsCredited(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when an honest node claims credited slashed funds (success path).
    event SlashedFundsClaimed(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when the treasury slashed-fund share is credited for later pull.
    event TreasurySlashedCredited(
        address indexed treasury,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when the treasury pulls accrued slashed-fund credits.
    event TreasurySlashedClaimed(
        address indexed treasury,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when work allocation is updated
    event WorkAllocationUpdated(WorkValueAllocation allocation);
    /// @notice Emitted when an E3 freezes its settlement policy.
    event E3PolicySnapshotted(
        uint256 indexed e3Id,
        uint64 indexed version,
        address indexed treasury,
        address interfold,
        address registry,
        address bondingRegistry,
        address slashingManager,
        WorkValueAllocation allocation
    );
    /// @notice Emitted when an expelling proposal starts or reaches a final outcome.
    event ExpulsionProposalStatusChanged(
        uint256 indexed e3Id,
        uint256 indexed proposalId,
        address indexed operator,
        bool pending,
        bool expelled
    );
    /// @notice Emitted when a successful E3 holds an accused operator's reward.
    event SuccessRewardHeld(
        uint256 indexed e3Id,
        address indexed operator,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when an account claims a released or reallocated reward.
    event HeldSuccessRewardClaimed(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );
    /// @notice Emitted when the last expelling proposal against an operator
    ///         clears and its held allocations become claimable again.
    event OperatorRewardsReleased(
        uint256 indexed e3Id,
        address indexed operator,
        uint256 heldSuccess,
        uint256 heldSlash
    );
    /// @notice Emitted when an E3 freezes an operator's reward recipient.
    event RewardRecipientSnapshotted(
        uint256 indexed e3Id,
        address indexed operator,
        address indexed recipient
    );
    /// @notice Emitted when the Interfold address is set
    event InterfoldSet(address indexed interfold);
    /// @notice Emitted when the treasury address is set
    event TreasurySet(address indexed treasury);
    ////////////////////////////////////////////////////////////
    //                                                        //
    //                        Errors                          //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice E3 is not in failed state
    error E3NotFailed(uint256 e3Id);
    /// @notice Refund already claimed
    error AlreadyClaimed(uint256 e3Id, address claimant);
    /// @notice Not the requester
    error NotRequester(uint256 e3Id, address caller);
    /// @notice Not an honest node
    error NotHonestNode(uint256 e3Id, address caller);
    /// @notice Refund not calculated yet
    error RefundNotCalculated(uint256 e3Id);
    /// @notice No refund available
    error NoRefundAvailable(uint256 e3Id);
    /// @notice Caller not authorized
    error Unauthorized();
    /// @notice Caller has no pending balance to claim
    error NothingToClaim();
    /// @notice Recorded liabilities exceed the manager's balance of a token.
    error InsolventToken(IERC20 token, uint256 liability, uint256 balance);
    /// @notice Failure reason has no configured economic responsibility.
    error InvalidFailureReason(IInterfold.FailureReason reason);
    /// @notice The operator already has a reward recipient for this E3.
    error RewardRecipientAlreadySnapshotted(uint256 e3Id, address operator);
    /// @notice The operator has no reward recipient for this E3.
    error RewardRecipientNotSnapshotted(uint256 e3Id, address operator);
    /// @notice The proposal is not pending in this E3's entitlement ledger.
    error ExpulsionProposalNotPending(uint256 e3Id, uint256 proposalId);
    /// @notice The operator's reward remains held by an unresolved proposal.
    error RewardPendingExpulsion(uint256 e3Id, address operator);
    /// @notice A proposal tried to settle a different ticket token for the E3.
    error SlashTokenMismatch(IERC20 expected, IERC20 actual);
    /// @notice Held successful rewards for one E3 must use one fee token.
    error RewardTokenMismatch(IERC20 expected, IERC20 actual);

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                      Functions                         //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice Calculate refund distribution for a failed E3
    /// @param e3Id The failed E3 ID
    /// @param originalPayment The original payment amount
    /// @param honestNodes Array of honest node addresses
    /// @param paymentToken The fee token that was used for this E3's payment
    function calculateRefund(
        uint256 e3Id,
        uint256 originalPayment,
        address[] calldata honestNodes,
        IERC20 paymentToken
    ) external;

    /// @notice Return the party whose collateral pays completed work for a failure reason.
    /// @dev Requester failures pay completed work from fee escrow. Ciphernode/supply
    ///      failures return all fee escrow and use actual ticket slashes to pay honest nodes.
    function getFailurePayer(
        IInterfold.FailureReason reason
    ) external pure returns (FailurePayer payer);

    /// @notice Freeze the current allocation, treasury, and E3 dependencies.
    /// @dev Only Interfold may call this, exactly once, during request creation.
    function snapshotE3Policy(uint256 e3Id, address registry) external;

    /// @notice Freeze reward recipients when an E3 committee is finalized.
    /// @dev Only the Interfold contract assigned to the E3 may call this once.
    function snapshotRewardRecipients(
        uint256 e3Id,
        address[] calldata operators
    ) external;

    /// @notice Return an operator's frozen reward recipient for an E3.
    function rewardRecipient(
        uint256 e3Id,
        address operator
    ) external view returns (address recipient);

    /// @notice Return the frozen recipient and whether its E3 reward is held.
    function rewardDisposition(
        uint256 e3Id,
        address operator
    ) external view returns (address recipient, bool held);

    /// @notice Return the frozen recipient and the operator's current reward
    ///         eligibility for an E3.
    /// @dev `pending` is true while any expelling proposal remains unresolved.
    ///      `excluded` is true after an executed expulsion. A payout requires
    ///      both to be false. Unlike `rewardDisposition`, this reports the
    ///      executed outcome, so a claim path can reject a forfeited reward.
    function rewardStatus(
        uint256 e3Id,
        address operator
    ) external view returns (address recipient, bool pending, bool excluded);

    /// @notice Record an unresolved proposal that can expel a committee member.
    function openExpulsionProposal(
        uint256 e3Id,
        uint256 proposalId,
        address operator
    ) external;

    /// @notice Resolve an expelling proposal and release or reallocate held rewards.
    function resolveExpulsionProposal(
        uint256 e3Id,
        uint256 proposalId,
        bool expelled
    ) external;

    /// @notice Hold one successful-E3 reward while expulsion is unresolved.
    function holdSuccessReward(
        uint256 e3Id,
        address operator,
        IERC20 token,
        uint256 amount
    ) external;

    /// @notice Claim a released or reallocated successful-E3 reward.
    function claimHeldSuccessReward(
        uint256 e3Id
    ) external returns (uint256 amount);

    /// @notice Pay `account` its claimable successful-E3 rewards for one E3.
    /// @dev Callable only by the E3's Interfold, which routes `claimReward`
    ///      here. Returns 0 instead of reverting so batch claims can skip an
    ///      empty E3. Held and forfeited allocations are excluded.
    function claimHeldSuccessRewardFor(
        uint256 e3Id,
        address account
    ) external returns (uint256 amount);

    /// @notice Pay an operator's held successful-E3 reward to its frozen recipient.
    /// @dev Permissionless. Reverts while an expelling proposal is pending and
    ///      after an executed expulsion forfeited the allocation.
    function claimOperatorHeldSuccessReward(
        uint256 e3Id,
        address operator
    ) external returns (uint256 amount);

    /// @notice Pay an operator's held slash share to its frozen recipient.
    /// @dev Permissionless. Same eligibility rule as
    ///      {claimOperatorHeldSuccessReward}.
    function claimOperatorSlashedFunds(
        uint256 e3Id,
        address operator
    ) external returns (uint256 amount);

    /// @notice Return how much of a holder's held slash share came from one penalty target.
    /// @dev ZEN2-20 follow-up. The sum over every target equals `heldSlash`.
    function heldSlashFrom(
        uint256 e3Id,
        address holder,
        address target
    ) external view returns (uint256 amount);

    /// @notice Return an operator's held successful-E3 reward and slash share.
    function operatorHeldRewards(
        uint256 e3Id,
        address operator
    ) external view returns (uint256 heldSuccess, uint256 heldSlash);

    /// @notice Return an account's released successful-E3 reward.
    function pendingHeldSuccessReward(
        uint256 e3Id,
        address account
    ) external view returns (uint256 amount);

    /// @notice Requester claims their refund
    /// @param e3Id The failed E3 ID
    /// @return amount The amount claimed
    function claimRequesterRefund(
        uint256 e3Id
    ) external returns (uint256 amount);

    /// @notice An honest operator's bond owner claims its reward.
    /// @param e3Id The failed E3 ID
    /// @param operator The honest operator whose reward is being claimed
    /// @return amount The amount claimed
    function claimHonestNodeReward(
        uint256 e3Id,
        address operator
    ) external returns (uint256 amount);

    /// @notice Escrow slashed funds. The destination is decided at terminal state.
    /// @param e3Id The E3 ID.
    /// @param proposalId The proposal that produced the funds.
    /// @param operator The operator whose collateral was slashed.
    /// @param token The actual ticket-underlying token transferred into escrow.
    /// @param amount The slashed amount.
    function escrowSlashedFunds(
        uint256 e3Id,
        uint256 proposalId,
        address operator,
        IERC20 token,
        uint256 amount
    ) external;

    /// @notice Settle one proposal after the E3 reaches a terminal state.
    function settleSlashedFunds(uint256 e3Id, uint256 proposalId) external;

    /// @notice Pull a token-specific slashed-fund entitlement.
    function claimSlashedFunds(
        uint256 e3Id,
        IERC20 token
    ) external returns (uint256 amount);

    /// @notice Pending, unsettled slash escrow for an E3 and token.
    function pendingSlashedFunds(
        uint256 e3Id,
        IERC20 token
    ) external view returns (uint256 amount);

    /// @notice Token-specific slash entitlement for an account.
    function pendingSlashedClaim(
        uint256 e3Id,
        IERC20 token,
        address account
    ) external view returns (uint256 amount);

    /// @notice Total protected liabilities recorded for a token.
    function tokenLiability(IERC20 token) external view returns (uint256);

    /// @notice Distribute escrowed slashed funds on success
    /// @param e3Id The E3 ID
    /// @param paymentToken The fee token for this E3
    function distributeSlashedFundsOnSuccess(
        uint256 e3Id,
        IERC20 paymentToken
    ) external;

    /// @notice Get refund distribution for an E3
    /// @param e3Id The E3 ID
    /// @return distribution The refund distribution
    function getRefundDistribution(
        uint256 e3Id
    ) external view returns (RefundDistribution memory distribution);

    /// @notice Check whether an address claimed the requester-refund role
    function hasRequesterClaimed(
        uint256 e3Id,
        address claimant
    ) external view returns (bool claimed);

    /// @notice Check whether an honest operator's owner claimed its reward.
    function hasHonestNodeClaimed(
        uint256 e3Id,
        address operator
    ) external view returns (bool claimed);

    /// @notice Set work value allocation
    /// @param allocation The new work allocation
    function setWorkAllocation(
        WorkValueAllocation calldata allocation
    ) external;

    /// @notice Get current work allocation
    /// @return allocation The current work allocation
    function getWorkAllocation()
        external
        view
        returns (WorkValueAllocation memory allocation);

    /// @notice Return the settlement policy frozen for an E3.
    function getE3PolicySnapshot(
        uint256 e3Id
    ) external view returns (E3PolicySnapshot memory snapshot);

    /// @notice Treasury pulls accrued credits (protocol slashed-fund share + dust).
    /// @dev Caller must be the treasury that was credited.
    function treasuryClaim(IERC20 token) external returns (uint256 amount);

    /// @notice Get pending treasury credits for a (treasury, token) pair.
    function pendingTreasuryClaim(
        address treasury,
        IERC20 token
    ) external view returns (uint256);
}
