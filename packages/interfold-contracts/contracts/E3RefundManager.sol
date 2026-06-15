// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;
import {
    Ownable2StepUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { IE3RefundManager } from "./interfaces/IE3RefundManager.sol";
import { IInterfold } from "./interfaces/IInterfold.sol";
import { IBondingRegistry } from "./interfaces/IBondingRegistry.sol";

/**
 * @title E3RefundManager
 * @notice Manages refund distribution for failed E3 computations
 * @dev Implements fault-attribution based refund system
 *
 */
contract E3RefundManager is IE3RefundManager, Ownable2StepUpgradeable {
    using SafeERC20 for IERC20;
    ////////////////////////////////////////////////////////////
    //                                                        //
    //                 Storage Variables                      //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice The Interfold contract (contains lifecycle functionality)
    IInterfold public interfold;
    /// @notice The bonding registry for node rewards
    IBondingRegistry public bondingRegistry;
    /// @notice Protocol treasury for protocol fee collection
    address public treasury;
    /// @notice Work value allocation configuration
    WorkValueAllocation internal _workAllocation;
    /// @notice Maps E3 ID to refund distribution
    mapping(uint256 e3Id => RefundDistribution distribution)
        internal _distributions;
    /// @notice Tracks claims per E3 per address
    mapping(uint256 e3Id => mapping(address claimer => bool hasClaimed))
        internal _claimed;
    /// @notice Tracks number of claims made per E3
    mapping(uint256 e3Id => uint256 count) internal _claimCount;
    /// @notice Tracks number of honest node claims made per E3
    mapping(uint256 e3Id => uint256 count) internal _honestNodeClaimCount;
    /// @notice Tracks total amount paid to honest nodes per E3
    mapping(uint256 e3Id => uint256 amount) internal _totalHonestNodePaid;
    /// @notice Maps E3 ID to honest node addresses
    mapping(uint256 e3Id => address[] nodes) internal _honestNodes;
    /// @notice Pending slashed funds awaiting E3 terminal state
    mapping(uint256 e3Id => uint256 amount) internal _pendingSlashedFunds;

    /// @notice Pull-payment ledger for success-path slashed-fund credits (e3Id => node => amount)
    mapping(uint256 e3Id => mapping(address account => uint256 amount))
        internal _pendingSlashedSuccess;
    /// @notice Snapshotted payment token for success-path slashed-fund credits
    mapping(uint256 e3Id => IERC20 token) internal _slashedSuccessToken;
    /// @notice Treasury pull-payment ledger for protocol slashed-fund share and dust.
    /// @dev Per-treasury so historical treasuries can drain even after rotation.
    mapping(address treasury => mapping(IERC20 token => uint256 amount))
        internal _pendingTreasury;
    ////////////////////////////////////////////////////////////
    //                                                        //
    //                       Modifiers                        //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice Restricts function to Interfold contract only
    modifier onlyInterfold() {
        if (msg.sender != address(interfold)) revert Unauthorized();
        _;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Initialization                       //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @notice Constructor that disables initializers
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the E3RefundManager contract
    /// @param _owner The owner address
    /// @param _interfold The Interfold contract address
    /// @param _treasury The protocol treasury address
    function initialize(
        address _owner,
        address _interfold,
        address _treasury
    ) public initializer {
        require(_owner != address(0), "Invalid owner");
        __Ownable_init(msg.sender);

        require(_interfold != address(0), "Invalid interfold");
        require(_treasury != address(0), "Invalid treasury");

        interfold = IInterfold(_interfold);
        bondingRegistry = interfold.bondingRegistry();
        treasury = _treasury;

        _workAllocation = WorkValueAllocation({
            committeeFormationBps: 1000,
            dkgBps: 3000,
            decryptionBps: 5500,
            protocolBps: 500,
            successSlashedNodeBps: 5000
        });

        if (_owner != owner()) _transferOwnership(_owner);
    }

    /// @notice Maximum protocol share within {WorkValueAllocation}.
    uint16 public constant MAX_PROTOCOL_BPS = 5_000;

    /// @notice Basis-points denominator (100% = 10_000 bps).
    uint16 internal constant BPS_BASE = 10_000;

    /// @notice Thrown when {renounceOwnership} is called.
    error RenounceOwnershipDisabled();

    /// @notice Emitted whenever {interfold} is updated.
    event InterfoldUpdated(address indexed previous, address indexed next);

    /// @notice Emitted whenever {treasury} is updated.
    event TreasuryUpdated(address indexed previous, address indexed next);

    /// @notice Disabled. Reverts unconditionally.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //               Refund Calculation                       //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @inheritdoc IE3RefundManager
    function calculateRefund(
        uint256 e3Id,
        uint256 originalPayment,
        address[] calldata honestNodes,
        IERC20 paymentToken
    ) external onlyInterfold {
        require(!_distributions[e3Id].calculated, "Already calculated");
        require(originalPayment > 0, "No payment");
        require(address(paymentToken) != address(0), "Invalid fee token");

        // Calculate work value based on stage
        IInterfold.E3Stage failedAt = _getFailedAtStage(e3Id);
        (uint16 workCompletedBps, uint16 workRemainingBps) = calculateWorkValue(
            failedAt
        );

        // Calculate base distribution
        uint256 honestNodeAmount = (originalPayment * workCompletedBps) /
            BPS_BASE;
        uint256 requesterAmount = (originalPayment * workRemainingBps) /
            BPS_BASE;
        uint256 protocolAmount = originalPayment -
            honestNodeAmount -
            requesterAmount;

        // No honest nodes: fold work share into the requester refund (mirrors
        // {Interfold._distributeRewards} success-path). Avoids per-failure dust
        // stranded outside `_pendingSlashedFunds` (which `withdrawOrphanedSlashedFunds`
        // cannot reach).
        if (honestNodes.length == 0 && honestNodeAmount > 0) {
            requesterAmount += honestNodeAmount;
            honestNodeAmount = 0;
        }

        // Store distribution. `perNodeAmount` is snapshotted below, AFTER any pending
        // slashed funds are folded in.
        _distributions[e3Id] = RefundDistribution({
            requesterAmount: requesterAmount,
            honestNodeAmount: honestNodeAmount,
            protocolAmount: protocolAmount,
            totalSlashed: 0,
            honestNodeCount: honestNodes.length,
            calculated: true,
            feeToken: paymentToken,
            originalPayment: originalPayment,
            perNodeAmount: 0
        });

        // Store honest nodes
        for (uint256 i = 0; i < honestNodes.length; i++) {
            _honestNodes[e3Id].push(honestNodes[i]);
        }

        // Credit protocol fee via pull-payment so a malicious/reverting/blacklisted
        // treasury cannot brick failed-E3 processing.
        if (protocolAmount > 0) {
            _pendingTreasury[treasury][paymentToken] += protocolAmount;
            emit TreasurySlashedCredited(
                treasury,
                paymentToken,
                protocolAmount
            );
        }

        // Apply any slashed funds that arrived before the distribution was calculated
        uint256 pending = _pendingSlashedFunds[e3Id];
        if (pending > 0) {
            _pendingSlashedFunds[e3Id] = 0;
            _applySlashedFunds(e3Id, pending);
        }

        // Snapshot per-honest-node payout AFTER folding in pre-distribution slashed
        // funds. `claimHonestNodeReward` reads this directly so the per-node payout
        // is immutable for the distribution's lifetime.
        RefundDistribution storage finalDist = _distributions[e3Id];
        if (honestNodes.length > 0) {
            finalDist.perNodeAmount =
                finalDist.honestNodeAmount /
                honestNodes.length;
        }

        emit RefundDistributionCalculated(
            e3Id,
            finalDist.requesterAmount,
            finalDist.honestNodeAmount,
            finalDist.protocolAmount,
            finalDist.totalSlashed
        );
    }

    /// @notice Get the stage at which E3 failed (for work calculation)
    function _getFailedAtStage(
        uint256 e3Id
    ) internal view returns (IInterfold.E3Stage) {
        IInterfold.FailureReason reason = interfold.getFailureReason(e3Id);

        // Map failure reason to stage
        if (
            reason == IInterfold.FailureReason.CommitteeFormationTimeout ||
            reason == IInterfold.FailureReason.InsufficientCommitteeMembers
        ) {
            return IInterfold.E3Stage.Requested;
        }
        if (
            reason == IInterfold.FailureReason.DKGTimeout ||
            reason == IInterfold.FailureReason.DKGInvalidShares
        ) {
            return IInterfold.E3Stage.CommitteeFinalized;
        }
        if (reason == IInterfold.FailureReason.NoInputsReceived) {
            return IInterfold.E3Stage.KeyPublished;
        }
        if (
            reason == IInterfold.FailureReason.ComputeTimeout ||
            reason == IInterfold.FailureReason.ComputeProviderExpired ||
            reason == IInterfold.FailureReason.ComputeProviderFailed ||
            reason == IInterfold.FailureReason.RequesterCancelled
        ) {
            return IInterfold.E3Stage.KeyPublished;
        }
        if (
            reason == IInterfold.FailureReason.DecryptionTimeout ||
            reason == IInterfold.FailureReason.DecryptionInvalidShares ||
            reason == IInterfold.FailureReason.VerificationFailed
        ) {
            return IInterfold.E3Stage.CiphertextReady;
        }

        return IInterfold.E3Stage.None;
    }

    /// @inheritdoc IE3RefundManager
    function calculateWorkValue(
        IInterfold.E3Stage stage
    ) public view returns (uint16 workCompletedBps, uint16 workRemainingBps) {
        WorkValueAllocation memory alloc = _workAllocation;

        if (
            stage == IInterfold.E3Stage.Requested ||
            stage == IInterfold.E3Stage.None
        ) {
            // Failed at Requested = no work done
            workCompletedBps = 0;
        } else if (stage == IInterfold.E3Stage.CommitteeFinalized) {
            // Failed during DKG = sortition work done
            workCompletedBps = alloc.committeeFormationBps;
        } else if (stage == IInterfold.E3Stage.KeyPublished) {
            // Failed during input phase = sortition + DKG done (no additional work)
            workCompletedBps = alloc.committeeFormationBps + alloc.dkgBps;
        } else if (stage == IInterfold.E3Stage.CiphertextReady) {
            // Failed during decryption = sortition + DKG done (awaiting decryption shares)
            workCompletedBps = alloc.committeeFormationBps + alloc.dkgBps;
        }

        workRemainingBps = BPS_BASE - workCompletedBps - alloc.protocolBps;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Claiming Functions                   //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @inheritdoc IE3RefundManager
    function claimRequesterRefund(
        uint256 e3Id
    ) external returns (uint256 amount) {
        RefundDistribution storage dist = _distributions[e3Id];
        if (!dist.calculated) revert RefundNotCalculated(e3Id);

        // Guard against pre-upgrade records where feeToken was not yet stored
        require(
            address(dist.feeToken) != address(0),
            "feeToken not initialized"
        );

        address requester = interfold.getRequester(e3Id);
        if (msg.sender != requester) revert NotRequester(e3Id, msg.sender);

        if (_claimed[e3Id][msg.sender]) revert AlreadyClaimed(e3Id, msg.sender);

        amount = dist.requesterAmount;
        if (amount == 0) revert NoRefundAvailable(e3Id);

        _claimed[e3Id][msg.sender] = true;
        _claimCount[e3Id]++;

        // Use the per-E3 fee token (not the global one, which may have been rotated)
        dist.feeToken.safeTransfer(msg.sender, amount);

        emit RefundClaimed(e3Id, msg.sender, amount, "REQUESTER");
    }

    /// @inheritdoc IE3RefundManager
    function claimHonestNodeReward(
        uint256 e3Id
    ) external returns (uint256 amount) {
        RefundDistribution storage dist = _distributions[e3Id];
        require(dist.calculated, RefundNotCalculated(e3Id));

        // Guard against pre-upgrade records where feeToken was not yet stored
        require(
            address(dist.feeToken) != address(0),
            "feeToken not initialized"
        );

        require(!_claimed[e3Id][msg.sender], AlreadyClaimed(e3Id, msg.sender));

        // Check if caller is honest node
        address[] memory nodes = _honestNodes[e3Id];
        bool isHonest = false;
        for (uint256 i = 0; i < nodes.length && !isHonest; i++) {
            isHonest = (nodes[i] == msg.sender);
        }
        require(isHonest, NotHonestNode(e3Id, msg.sender));

        require(dist.honestNodeCount > 0, NoRefundAvailable(e3Id));
        // Read the snapshot taken at `calculateRefund` time — immutable for the
        // distribution's lifetime; post-claim slashed funds are routed to
        // `_pendingSlashedFunds` and never mutate `dist.honestNodeAmount`.
        uint256 perNodeAmount = dist.perNodeAmount;
        require(perNodeAmount > 0, NoRefundAvailable(e3Id));

        amount = perNodeAmount;
        _honestNodeClaimCount[e3Id]++;
        if (_honestNodeClaimCount[e3Id] == dist.honestNodeCount) {
            // Route rounding dust to treasury via pull-payment so a reverting/blacklisted
            // treasury cannot brick the last honest claim. Computed from the snapshot so
            // the final claim is deterministic.
            uint256 paidIncludingThis = _totalHonestNodePaid[e3Id] +
                perNodeAmount;
            uint256 dust = dist.honestNodeAmount > paidIncludingThis
                ? dist.honestNodeAmount - paidIncludingThis
                : 0;
            if (dust > 0) {
                _pendingTreasury[treasury][dist.feeToken] += dust;
                emit TreasurySlashedCredited(treasury, dist.feeToken, dust);
            }
        }
        _totalHonestNodePaid[e3Id] += amount;

        _claimed[e3Id][msg.sender] = true;
        _claimCount[e3Id]++;

        // Direct transfer to the honest node (refund path; bypasses BondingRegistry
        // distributor authorization and operator-registered checks).
        IERC20 token = dist.feeToken;
        token.safeTransfer(msg.sender, amount);

        emit RefundClaimed(e3Id, msg.sender, amount, "HONEST_NODE");
    }

    /// @inheritdoc IE3RefundManager
    function escrowSlashedFunds(
        uint256 e3Id,
        uint256 amount
    ) external onlyInterfold {
        require(amount > 0, "Zero amount");

        RefundDistribution storage dist = _distributions[e3Id];
        if (dist.calculated) {
            if (_claimCount[e3Id] == 0) {
                _applySlashedFunds(e3Id, amount);
            } else if (dist.honestNodeCount > 0) {
                // Distribution calculated and a claim has landed, but honest nodes existed.
                // Credit the latecomer slash to the honest committee (pull via
                // `claimSlashedFundsOnSuccess`) instead of orphaning to the treasury.
                // No double-pay risk: requester + unclaimed honest portions were already
                // settled by the initial `_applySlashedFunds`.
                IERC20 token = dist.feeToken;
                if (address(_slashedSuccessToken[e3Id]) == address(0)) {
                    _slashedSuccessToken[e3Id] = token;
                }
                address[] storage nodes = _honestNodes[e3Id];
                uint256 n = nodes.length;
                uint256 perNode = amount / n;
                uint256 distributed = 0;
                for (uint256 i = 0; i < n; i++) {
                    uint256 nodeAmount = perNode;
                    if (i == n - 1) {
                        nodeAmount = amount - distributed;
                    }
                    if (nodeAmount > 0) {
                        _pendingSlashedSuccess[e3Id][nodes[i]] += nodeAmount;
                        emit SlashedFundsCredited(
                            e3Id,
                            nodes[i],
                            token,
                            nodeAmount
                        );
                    }
                    distributed += nodeAmount;
                }
            } else {
                _pendingSlashedFunds[e3Id] += amount;
            }
        } else {
            _pendingSlashedFunds[e3Id] += amount;
        }

        emit SlashedFundsEscrowed(e3Id, amount);
    }

    /// @inheritdoc IE3RefundManager
    function distributeSlashedFundsOnSuccess(
        uint256 e3Id,
        address[] calldata honestNodes,
        IERC20 paymentToken
    ) external onlyInterfold {
        uint256 escrowed = _pendingSlashedFunds[e3Id];
        if (escrowed == 0) return;
        _pendingSlashedFunds[e3Id] = 0;

        require(address(paymentToken) != address(0), "Invalid fee token");
        _slashedSuccessToken[e3Id] = paymentToken;

        uint256 toNodes = (escrowed * _workAllocation.successSlashedNodeBps) /
            BPS_BASE;
        uint256 toProtocol = escrowed - toNodes;

        // Credit treasury share — pull only.
        if (toProtocol > 0) {
            _pendingTreasury[treasury][paymentToken] += toProtocol;
            emit TreasurySlashedCredited(treasury, paymentToken, toProtocol);
        }

        if (toNodes > 0 && honestNodes.length > 0) {
            uint256 perNode = toNodes / honestNodes.length;
            uint256 distributed = 0;
            for (uint256 i = 0; i < honestNodes.length; i++) {
                uint256 nodeAmount = perNode;
                if (i == honestNodes.length - 1) {
                    nodeAmount = toNodes - distributed;
                }
                if (nodeAmount > 0) {
                    // credit per-node so one blacklisted/reverting recipient
                    // does not brick payouts for the rest of the committee.
                    _pendingSlashedSuccess[e3Id][honestNodes[i]] += nodeAmount;
                    emit SlashedFundsCredited(
                        e3Id,
                        honestNodes[i],
                        paymentToken,
                        nodeAmount
                    );
                }
                distributed += nodeAmount;
            }
        } else if (toNodes > 0) {
            // No honest nodes — funnel the node share to treasury for governance triage.
            _pendingTreasury[treasury][paymentToken] += toNodes;
            emit TreasurySlashedCredited(treasury, paymentToken, toNodes);
        }

        emit SlashedFundsDistributedOnSuccess(e3Id, toNodes, toProtocol);
    }

    /// @notice Apply slashed funds to an E3's refund distribution
    /// @dev This function is ONLY called on the failure path.Priority: make requester whole first,
    ///      then distribute remainder to honest nodes.
    ///      The requester is filled up to their original E3 payment before honest nodes receive
    ///      any portion, ensuring the party who paid for the computation is compensated first.
    /// @param e3Id The E3 ID
    /// @param amount The slashed amount to apply
    function _applySlashedFunds(uint256 e3Id, uint256 amount) internal {
        RefundDistribution storage dist = _distributions[e3Id];

        // Priority: make requester whole first
        // requesterGap = how much more the requester needs to reach their original payment
        uint256 requesterGap = dist.originalPayment > dist.requesterAmount
            ? dist.originalPayment - dist.requesterAmount
            : 0;
        uint256 toRequester = amount >= requesterGap ? requesterGap : amount;
        uint256 toHonestNodes = amount - toRequester;

        // No honest nodes: residual would be unclaimable (`claimHonestNodeReward`
        // reverts and `withdrawOrphanedSlashedFunds` only drains `_pendingSlashedFunds`).
        // Route to treasury pull-pool; requester cap (originalPayment) is preserved.
        if (dist.honestNodeCount == 0 && toHonestNodes > 0) {
            IERC20 token = dist.feeToken;
            if (address(token) != address(0)) {
                _pendingTreasury[treasury][token] += toHonestNodes;
                emit TreasurySlashedCredited(treasury, token, toHonestNodes);
            }
            toHonestNodes = 0;
        }

        dist.requesterAmount += toRequester;
        dist.honestNodeAmount += toHonestNodes;
        dist.totalSlashed += amount;

        // Re-snapshot perNodeAmount for the pre-first-claim path (gated by
        // `_claimCount==0` in `escrowSlashedFunds`). Post-first-claim funds bypass
        // this code via `_pendingSlashedFunds`, so the snapshot stays immutable
        // across the claim window.
        if (dist.honestNodeCount > 0) {
            dist.perNodeAmount = dist.honestNodeAmount / dist.honestNodeCount;
        }

        emit SlashedFundsApplied(e3Id, toRequester, toHonestNodes);
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                    View Functions                      //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @inheritdoc IE3RefundManager
    function getRefundDistribution(
        uint256 e3Id
    ) external view returns (RefundDistribution memory) {
        return _distributions[e3Id];
    }

    /// @inheritdoc IE3RefundManager
    function hasClaimed(
        uint256 e3Id,
        address claimant
    ) external view returns (bool) {
        return _claimed[e3Id][claimant];
    }

    /// @inheritdoc IE3RefundManager
    function getWorkAllocation()
        external
        view
        returns (WorkValueAllocation memory)
    {
        return _workAllocation;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Admin Functions                      //
    //                                                        //
    ////////////////////////////////////////////////////////////
    /// @inheritdoc IE3RefundManager
    function setWorkAllocation(
        WorkValueAllocation calldata allocation
    ) external onlyOwner {
        // cap protocol BPS at 50% so a malicious owner cannot route
        // an arbitrary share of fees to the protocol treasury.
        require(
            allocation.protocolBps <= MAX_PROTOCOL_BPS,
            "Protocol BPS too high"
        );
        uint256 total = uint256(allocation.committeeFormationBps) +
            uint256(allocation.dkgBps) +
            uint256(allocation.decryptionBps) +
            uint256(allocation.protocolBps);
        require(total == BPS_BASE, "Must sum to 10000");
        require(allocation.successSlashedNodeBps <= BPS_BASE, "Invalid BPS");

        _workAllocation = allocation;

        emit WorkAllocationUpdated(allocation);
    }

    /// @notice Set the Interfold contract address
    /// @param _interfold New Interfold address
    function setInterfold(address _interfold) external onlyOwner {
        require(_interfold != address(0), "Invalid interfold");
        address oldValue = address(interfold);
        interfold = IInterfold(_interfold);
        emit InterfoldUpdated(oldValue, _interfold);
    }

    /// @notice Set the treasury address
    /// @param _treasury New treasury address
    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0), "Invalid treasury");
        address oldValue = treasury;
        treasury = _treasury;
        emit TreasuryUpdated(oldValue, _treasury);
    }

    /// @notice Recover orphaned slashed funds for an E3 that has already completed
    ///         or whose failure was already fully processed.
    /// @dev When a slash executes after an E3 has completed (or after failure claims
    ///      have started), funds accumulate in `_pendingSlashedFunds` with no drain
    ///      path. This function allows the owner to redirect them to the treasury.
    ///      Only callable when the E3 is in a terminal state (Complete or Failed)
    ///      and the funds cannot be distributed through normal channels.
    /// @param e3Id The E3 ID
    /// @param paymentToken The token the slashed funds are denominated in
    function withdrawOrphanedSlashedFunds(
        uint256 e3Id,
        IERC20 paymentToken
    ) external onlyOwner {
        uint256 amount = _pendingSlashedFunds[e3Id];
        require(amount > 0, "No orphaned funds");

        // Only allow withdrawal when E3 is in a terminal state
        IInterfold.E3Stage stage = interfold.getE3Stage(e3Id);
        require(
            stage == IInterfold.E3Stage.Complete ||
                stage == IInterfold.E3Stage.Failed,
            "E3 not in terminal state"
        );

        // If E3 is Failed and distribution hasn't been calculated yet,
        // funds should flow through the normal processE3Failure path
        if (stage == IInterfold.E3Stage.Failed) {
            RefundDistribution storage dist = _distributions[e3Id];
            require(dist.calculated, "Use processE3Failure first");
            // refuse to redirect to treasury when honest nodes existed — the
            // latecomer crediting in `escrowSlashedFunds` should have routed funds
            // to them. Reaching this branch with honest nodes implies an invariant
            // violation that governance must triage off-chain.
            require(
                dist.honestNodeCount == 0,
                "Honest nodes present; use slash crediting"
            );
        }

        _pendingSlashedFunds[e3Id] = 0;
        require(address(paymentToken) != address(0), "Invalid fee token");
        paymentToken.safeTransfer(treasury, amount);

        emit OrphanedSlashedFundsWithdrawn(e3Id, amount);
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              Pull-Payment Claim Functions              //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IE3RefundManager
    function claimSlashedFundsOnSuccess(
        uint256 e3Id
    ) external returns (uint256 amount) {
        amount = _claimSlashedFundsOnSuccess(e3Id, msg.sender);
        require(amount > 0, NothingToClaim());
    }

    /// @inheritdoc IE3RefundManager
    function claimSlashedFundsOnSuccessBatch(
        uint256[] calldata e3Ids
    ) external {
        uint256 len = e3Ids.length;
        uint256 totalClaimed;
        for (uint256 i = 0; i < len; i++) {
            totalClaimed += _claimSlashedFundsOnSuccess(e3Ids[i], msg.sender);
        }
        require(totalClaimed > 0, NothingToClaim());
    }

    function _claimSlashedFundsOnSuccess(
        uint256 e3Id,
        address account
    ) internal returns (uint256 amount) {
        amount = _pendingSlashedSuccess[e3Id][account];
        if (amount == 0) return 0;
        _pendingSlashedSuccess[e3Id][account] = 0;
        IERC20 token = _slashedSuccessToken[e3Id];
        token.safeTransfer(account, amount);
        emit SlashedFundsClaimed(e3Id, account, token, amount);
    }

    /// @inheritdoc IE3RefundManager
    function pendingSlashedFundsOnSuccess(
        uint256 e3Id,
        address account
    ) external view returns (uint256) {
        return _pendingSlashedSuccess[e3Id][account];
    }

    /// @inheritdoc IE3RefundManager
    function treasuryClaim(IERC20 token) external returns (uint256 amount) {
        amount = _pendingTreasury[msg.sender][token];
        require(amount > 0, NothingToClaim());
        _pendingTreasury[msg.sender][token] = 0;
        token.safeTransfer(msg.sender, amount);
        emit TreasurySlashedClaimed(msg.sender, token, amount);
    }

    /// @inheritdoc IE3RefundManager
    function pendingTreasuryClaim(
        address treasuryAddr,
        IERC20 token
    ) external view returns (uint256) {
        return _pendingTreasury[treasuryAddr][token];
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              ERC-165 Interface Detection               //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice ERC-165 interface detection. Advertises
    ///         {IE3RefundManager} and {IERC165}.
    function supportsInterface(
        bytes4 interfaceId
    ) external pure virtual returns (bool) {
        return
            interfaceId == type(IE3RefundManager).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }

    /// @dev Reserved storage slots for future upgrades.
    // solhint-disable-next-line var-name-mixedcase
    uint256[50] private __gap;
}
