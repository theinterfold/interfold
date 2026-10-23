// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ICiphernodeRegistry } from "./ICiphernodeRegistry.sol";
import { InterfoldTicketToken } from "../token/InterfoldTicketToken.sol";
import { IBondedCheckpoints } from "./IBondedCheckpoints.sol";

/**
 * @title IBondingRegistry
 * @notice Interface for the main bonding registry that holds operator balance and ciphernode bonds
 */
interface IBondingRegistry {
    function numRegisteredOperators() external view returns (uint256);

    function unresolvedCommitteeCount() external view returns (uint256);

    /// @notice Number of unreleased committees that hold the collateral of `operator`.
    /// @dev While it is not zero, `claimExitsFor` reverts with `OperatorInActiveCommittee`.
    function unresolvedCommitteesOf(
        address operator
    ) external view returns (uint256);

    /// @notice An unreleased committee that holds the collateral of `operator`.
    /// @dev Indexes run from 0 to `unresolvedCommitteesOf(operator) - 1`, in no fixed order. A
    ///      committee requested before this registry version tracked committees has no index, so
    ///      for an operator in one, the last indexes revert with `CommitteeObligationNotTracked`.
    ///      The `CommitteeObligationUpdated` events list those committees.
    /// @return e3Id The E3 of the committee
    /// @return registry The request-time registry that owns the committee
    function committeeObligationAt(
        address operator,
        uint256 index
    ) external view returns (uint256 e3Id, address registry);

    /// @notice Bonding assets and every raw-unit value denominated in them.
    struct BondingAssetConfig {
        address ticketToken;
        address ciphernodeBondToken;
        uint256 ticketPrice;
        uint256 requiredCiphernodeBond;
        uint8 expectedTicketDecimals;
        uint8 expectedCiphernodeBondDecimals;
    }

    // ======================
    // Custom Errors
    // ======================

    // General
    /// @notice Emitted when the bonded-history contract is configured.
    event BondedCheckpointsSet(address indexed checkpoints);

    /// @notice Emitted when ciphernode-bond-token rotation detaches the bonded-history contract.
    event BondedCheckpointsDetached(address indexed previousCheckpoints);

    error ZeroAddress();
    error ZeroAmount();
    error CiphernodeBanned();
    error Unauthorized();
    error InsufficientBalance();
    error NotCiphernodeBonded();
    error AlreadyRegistered();
    error NotRegistered();
    error ExitInProgress();
    error ExitNotReady();
    error InvalidAmount();

    /// @notice A bonding-asset transfer delivered a different amount than requested.
    error AssetTransferMismatch(
        address asset,
        uint256 expected,
        uint256 actual
    );

    /// @notice A bonding asset must be a deployed contract (except the one-time
    ///         zero ciphernode-bond-token placeholder used during circular deployment).
    error InvalidBondingAsset(address asset);

    /// @notice The configured ciphernode bond token does not provide a valid locked balance.
    error IncompatibleCiphernodeBondToken(address token);

    /// @notice A bonding asset cannot rotate while balances remain denominated in it.
    error OutstandingAssetLiabilities(address asset, uint256 amount);

    /// @notice A bonding asset does not expose a valid ERC-20 decimals value.
    error BondingAssetDecimalsUnavailable(address asset);

    /// @notice A bonding asset decimals value does not match its configuration.
    error BondingAssetDecimalsMismatch(
        address asset,
        uint8 expected,
        uint8 actual
    );

    /// @notice The ticket token authorizes a different collateral registry.
    error TicketTokenRegistryMismatch(address configured, address expected);

    /// @notice Asset rotation is blocked by unfinished work owned by a manager.
    error AssetConfigurationInUse(
        address manager,
        uint256 e3Assignments,
        uint256 openSlashLocks,
        uint256 pendingRoutes
    );

    error InvalidConfiguration();
    error NoPendingDeregistration();
    error OnlyRewardDistributor();
    error ArrayLengthMismatch();
    /// @notice Thrown when an operator attempts to withdraw collateral while any
    ///         financial slash proposal against them remains unresolved.
    error OperatorUnderSlash();

    /// @notice Matured collateral remains slashable until every selected
    ///         committee obligation for the operator reaches a terminal E3.
    error OperatorInActiveCommittee();

    /// @notice Treasury withdrawal or generic routing attempted to consume funds
    ///         reserved for a pending E3 slash route.
    error ReservedSlashedFunds();

    /// @notice The E3 has no frozen slash-fund destination for this manager.
    error SlashRouteDestinationNotFound(address manager, uint256 e3Id);

    /// @notice A proposal already has a slashed-ticket reservation.
    error SlashReservationAlreadyExists(address manager, uint256 proposalId);

    /// @notice A proposal has no slashed-ticket reservation.
    error SlashReservationNotFound(address manager, uint256 proposalId);

    /// @notice A manager still owns slash routes that must finish before revocation.
    error ManagerHasPendingSlashRoutes(address manager, uint256 count);

    /// @notice A manager still owns E3 assignments that must be closed before revocation.
    error ManagerHasE3Assignments(address manager, uint256 count);

    /// @notice A manager still owns proposal locks that must finish before revocation.
    error ManagerHasOpenSlashLocks(address manager, uint256 count);

    /// @notice A manager still owns bans that must be migrated or cleared before revocation.
    error ManagerHasActiveBans(address manager, uint256 count);

    /// @notice A manager does not implement the required immutable API.
    error IncompatibleSlashingManager(address manager);

    /// @notice A manager is configured for a different bonding registry.
    error SlashingManagerBondingMismatch(
        address manager,
        address configuredBondingRegistry
    );

    /// @notice A manager already recorded this proposal lock.
    error SlashLockAlreadyExists(address manager, uint256 proposalId);

    /// @notice A manager does not own the expected proposal lock.
    error SlashLockNotFound(address manager, uint256 proposalId);

    /// @notice An E3 slash assignment does not exist for this manager.
    error E3AssignmentNotFound(address manager, uint256 e3Id);

    /// @notice An E3 assignment cannot close before its lifecycle is terminal.
    error E3AssignmentNotTerminal(uint256 e3Id);

    /// @notice Thrown when {setExitDelay} input is outside the permitted range.
    error ExitDelayOutOfBounds(uint64 exitDelay);

    /// @notice `operator` has no tracked committee obligation at `index`.
    error CommitteeObligationNotTracked(address operator, uint256 index);

    /// @notice Exit collateral could unlock while snapshot tickets remain valid.
    error ExitDelayMustExceedSortitionWindow(
        uint256 exitDelay,
        uint256 requiredDelay
    );

    /// @notice Thrown when {setRewardDistributor} would exceed
    ///         {MAX_AUTHORIZED_DISTRIBUTORS}.
    error MaxAuthorizedDistributors();

    /// @notice Thrown when {renounceOwnership} is called.
    error RenounceOwnershipDisabled();

    /// @notice Thrown when a caller attempts to manage another operator's collateral.
    error NotBondOwner(address caller, address operator);

    /// @notice Thrown when an operator attempts to replace an already-authorized bond owner.
    error BondOwnerAlreadySet(address operator, address bondOwner);

    /// @notice Moving a ciphernode bond position would leave the previous owner with
    ///         less wallet-plus-bonded FOLD than its current locked balance.
    error BondOwnerTransferViolatesLock(
        address bondOwner,
        uint256 lockedBalance,
        uint256 controlledBalance
    );

    // ======================
    // Events (Protocol-Named)
    // ======================

    /// @notice Emitted when matured assets leave an operator's exit queue.
    event AssetsClaimed(
        address indexed operator,
        uint256 ticketAmount,
        uint256 ciphernodeBondAmount
    );

    /**
     * @notice Emitted when operator's ticket balance changes
     * @param operator Address of the operator
     * @param delta Change in balance (positive for increase, negative for decrease)
     * @param newBalance New total balance
     * @param reason Reason for the change (e.g., "DEPOSIT", "WITHDRAW", slash reason)
     */
    event TicketBalanceUpdated(
        address indexed operator,
        int256 delta,
        uint256 newBalance,
        bytes32 indexed reason
    );

    /**
     * @notice Emitted when operator's ciphernode bond changes
     * @param operator Address of the operator
     * @param delta Change in bond (positive for increase, negative for decrease)
     * @param newBond New total ciphernode bond
     * @param reason Reason for the change (e.g., "BOND", "UNBOND", slash reason)
     */
    event CiphernodeBondUpdated(
        address indexed operator,
        int256 delta,
        uint256 newBond,
        bytes32 indexed reason
    );

    /**
     * @notice Emitted when operator requests deregistration from the protocol
     * @param operator Address of the operator
     * @param unlockAt Timestamp when deregistration can be finalized
     */
    event CiphernodeDeregistrationRequested(
        address indexed operator,
        uint64 unlockAt
    );

    /**
     * @notice Emitted when operator active status changes
     * @param operator Address of the operator
     * @param active True if active, false if inactive
     */
    event OperatorActivationChanged(address indexed operator, bool active);

    /**
     * @notice Emitted when configuration is updated
     * @param parameter Name of the parameter
     * @param oldValue Previous value
     * @param newValue New value
     */
    event ConfigurationUpdated(
        bytes32 indexed parameter,
        uint256 oldValue,
        uint256 newValue
    );

    /**
     * @notice Emitted when an eligibility setting invalidates cached operator status.
     * @param version New eligibility-policy version.
     */
    event EligibilityConfigurationVersionUpdated(uint256 indexed version);

    /**
     * @notice Emitted when a reward distributor is authorized or revoked
     * @param distributor Address of the distributor
     * @param authorized True if authorized, false if revoked
     */
    event RewardDistributorUpdated(
        address indexed distributor,
        bool authorized
    );

    /**
     * @notice Emitted when treasury withdraws slashed funds
     * @param to Treasury address
     * @param ticketAmount Amount of slashed ticket balance withdrawn
     * @param ciphernodeBondAmount Amount of slashed ciphernode bond withdrawn
     */
    event SlashedFundsWithdrawn(
        address indexed to,
        uint256 ticketAmount,
        uint256 ciphernodeBondAmount
    );

    /**
     * @notice Emitted when the slashed funds treasury address is set
     * @param treasury Address of the slashed funds treasury
     */
    event SlashedFundsTreasurySet(address indexed treasury);

    /// @notice Emitted when both bonding asset configurations are updated.
    event BondingAssetConfigUpdated(
        InterfoldTicketToken indexed ticketToken,
        IERC20 indexed ciphernodeBondToken,
        uint256 ticketPrice,
        uint256 requiredCiphernodeBond,
        uint8 expectedTicketDecimals,
        uint8 expectedCiphernodeBondDecimals,
        uint64 indexed configurationVersion
    );

    /**
     * @notice Emitted when governance removes ciphernode bond tokens that are not
     *         backing any active bond, pending exit, or slashed-fund claim.
     * @param token Ciphernode bond token whose surplus was swept
     * @param to Slashed-funds treasury that received the surplus
     * @param amount Amount requested for transfer
     */
    event CiphernodeBondSurplusSwept(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    /**
     * @notice Emitted when the registry is set
     * @param registry Address of the registry
     */
    event RegistrySet(address indexed registry);

    /// @notice Emitted whenever the slashing manager address is updated.
    event SlashingManagerUpdated(
        address indexed previous,
        address indexed next
    );

    /// @notice Emitted whenever a slashing manager gains or loses authority.
    /// @dev Replaced managers remain authorized until governance explicitly
    ///      revokes them so snapshotted E3s and open proposals can finish.
    event SlashingManagerAuthorizationUpdated(
        address indexed slashingManager,
        bool authorized
    );

    /// @notice Emitted when an E3 freezes its slash-fund destination.
    event SlashRouteDestinationSnapshotted(
        address indexed slashingManager,
        uint256 indexed e3Id,
        address indexed refundManager
    );

    /// @notice Emitted when a terminal E3 releases its manager assignment.
    event SlashRouteDestinationReleased(
        address indexed slashingManager,
        uint256 indexed e3Id
    );

    /// @notice Emitted when a manager opens or closes one proposal lock.
    event SlashLockUpdated(
        address indexed slashingManager,
        uint256 indexed proposalId,
        address indexed operator,
        bool active
    );

    /// @notice Emitted when a manager changes its ban state for an operator.
    event ManagerBanUpdated(
        address indexed slashingManager,
        address indexed operator,
        bool banned
    );

    /// @notice Emitted when a request-time registry snapshots, opens, or
    ///         releases committee collateral obligations.
    event CommitteeObligationUpdated(
        uint256 indexed e3Id,
        address indexed registry,
        address indexed operator,
        bool active
    );

    /// @notice Emitted when a proposal reserves slashed ticket funds.
    event SlashedTicketFundsReserved(
        address indexed slashingManager,
        uint256 indexed proposalId,
        uint256 indexed e3Id,
        address refundManager,
        uint256 amount
    );

    /// @notice Emitted when a proposal routes its reserved ticket funds.
    event ReservedSlashedTicketFundsRouted(
        address indexed slashingManager,
        uint256 indexed proposalId,
        address indexed refundManager,
        uint256 amount
    );

    /**
     * @notice Emitted when the wallet that owns an operator's collateral is set.
     * @param operator Hot operator key used by the node
     * @param bondOwner Wallet that funds and controls the operator's collateral
     */
    event BondOwnerSet(address indexed operator, address indexed bondOwner);

    /**
     * @notice Emitted when the current owner proposes transferring an operator position.
     * @param operator Hot operator key used by the node
     * @param currentOwner Current wallet controlling the operator's collateral
     * @param pendingOwner Wallet that may accept ownership
     */
    event BondOwnerTransferProposed(
        address indexed operator,
        address indexed currentOwner,
        address indexed pendingOwner
    );

    // ======================
    // View Functions
    // ======================

    /**
     * @notice Get ciphernode bond token address
     * @return Ciphernode bond token address
     */
    function getCiphernodeBondToken() external view returns (address);

    /**
     * @notice Total ciphernode-bond-token obligations held by the registry.
     * @dev Covers active bonds, queued exits, and slashed funds awaiting
     *      treasury withdrawal.
     */
    function totalCiphernodeBondLiability() external view returns (uint256);

    /**
     * @notice Get ticket token address
     * @return Ticket token address
     */
    function getTicketToken() external view returns (address);

    /**
     * @notice Get operator's current ticket balance
     * @param operator Address of the operator
     * @return Current collateral balance
     */
    function getTicketBalance(address operator) external view returns (uint256);

    /**
     * @notice Get operator's current ciphernode bond
     * @param operator Address of the operator
     * @return Current ciphernode bond
     */
    function getCiphernodeBond(
        address operator
    ) external view returns (uint256);

    /**
     * @notice Get the wallet that owns and controls an operator's collateral.
     * @dev Returns address(0) until the operator authorizes an owner.
     */
    function bondOwnerOf(address operator) external view returns (address);

    /**
     * @notice Get the wallet currently nominated to accept an operator position.
     */
    function pendingBondOwnerOf(
        address operator
    ) external view returns (address);

    /**
     * @notice Get FOLD that still counts toward an account's locked-floor collateral.
     * @dev Includes active ciphernode bond plus pending FOLD exits that remain slashable/not returned.
     * @param account Bond owner whose aggregate FOLD bond credit is queried
     * @return Active plus pending ciphernode-bond amount
     */
    function totalBonded(address account) external view returns (uint256);

    /**
     * @notice Get the contract that records bonded history.
     * @dev Zero while unconfigured, and again after a ciphernode-bond-token rotation detaches it.
     * @return The checkpoint contract, or the zero address.
     */
    function bondedCheckpoints() external view returns (IBondedCheckpoints);

    /**
     * @notice Point this registry at the contract that records bonded history.
     * @dev Settable once per ciphernode bond token. Bonded FOLD is transferred to this registry and never
     * delegated, so without a recorded history an operator's bonded weight is invisible to
     * governance. The history lives off this contract because it is within a few hundred bytes of
     * the EIP-170 limit.
     *
     * Repointing while one is attached is refused: it would abandon the recorded history and
     * silently change every past answer. Rotating the ciphernode bond token detaches the current contract,
     * because the history counts ciphernode-bond-token units and a replacement token's bonds must not be
     * added to the previous token's voting power.
     *
     * The candidate must name this registry and must accept a write from it, which is checked by
     * synchronizing the zero address. Both are needed: other protocol contracts also answer
     * `registry()` with this address.
     * @param newCheckpoints The checkpoint contract, which must name this registry.
     */
    function setBondedCheckpoints(IBondedCheckpoints newCheckpoints) external;

    /**
     * @notice Record an owner's current bonded total in the checkpoint contract.
     * @dev Bonding that happened before `setBondedCheckpoints` left no history, because the sync
     * is a no-op while unconfigured. Without this, such an owner stays invisible to governance
     * until its next bond, slash, transfer or exit claim happens to record it.
     *
     * Permissionless and idempotent: it can only write the owner's true current total at the
     * current timepoint, so there is nothing to gain by calling it and no past entry it can
     * rewrite. Anyone may repair an owner's history, including a third party.
     * @param bondOwner The owner to record.
     */
    function resyncBondedCheckpoint(address bondOwner) external;

    /**
     * @notice Get current ticket price
     * @return Price per ticket in collateral token units
     */
    function ticketPrice() external view returns (uint256);

    /**
     * @notice Calculate available tickets for an operator
     * @param operator Address of the operator
     * @return Number of tickets available (floor(balance / ticketPrice))
     */
    function availableTickets(address operator) external view returns (uint256);

    /**
     * @notice Check if operator is bonded
     * @param operator Address of the operator
     * @return True if operator has sufficient ciphernode bond
     */
    function isCiphernodeBonded(address operator) external view returns (bool);

    /**
     * @notice Check if operator is registered
     * @param operator Address of the operator
     * @return True if operator is registered
     */
    function isRegistered(address operator) external view returns (bool);

    /**
     * @notice Check if operator is active
     * @param operator Address of the operator
     * @return True if operator is active (bonded, registered, and has min tickets)
     */
    function isActive(address operator) external view returns (bool);

    /**
     * @notice Check whether an operator was active at an EIP-6372 timepoint.
     * @param operator Address of the operator
     * @param timepoint Timestamp-mode checkpoint to query
     * @return active True when the operator satisfied the eligibility policy at that timepoint
     * @return activeOperatorCount Number of operators active at that timepoint
     */
    function eligibilityAt(
        address operator,
        uint256 timepoint
    ) external view returns (bool active, uint256 activeOperatorCount);

    /**
     * @notice Get the number of currently active operators
     * @return Number of active operators
     */
    function numActiveOperators() external view returns (uint256);

    /// @notice Current eligibility-policy version.
    function eligibilityConfigurationVersion() external view returns (uint256);

    /**
     * @notice Re-evaluate one registered operator under the current eligibility policy.
     * @dev Permissionless so operators or governance can restore current status after
     *      an eligibility configuration update. Address zero is reserved for the configured
     *      NodeReleaseRegistry to invalidate all cached statuses during a release cutover.
     */
    function refreshOperatorStatus(address operator) external;

    /**
     * @notice Re-evaluate a batch of registered operators under the current policy.
     * @dev Intended for governance/operator automation after a policy update.
     */
    function refreshOperatorStatuses(address[] calldata operators) external;

    /**
     * @notice Check if operator has deregistration in progress
     * @param operator Address of the operator
     * @return True if exit requested but not finalized
     */
    function hasExitInProgress(address operator) external view returns (bool);

    /**
     * @notice Get ciphernode bond price required
     * @return Ciphernode bond price amount
     */
    function requiredCiphernodeBond() external view returns (uint256);

    /// @notice Returns the current bonding-asset identity version.
    function bondingAssetConfigurationVersion() external view returns (uint64);

    /**
     * @notice Get minimum ticket balance required for activation
     * @return Minimum number of tickets required
     */
    function minTicketBalance() external view returns (uint256);

    /**
     * @notice Get exit delay period
     * @return Number of seconds operators must wait after requesting exit
     */
    function exitDelay() external view returns (uint64);

    /**
     * @notice Get an operator's ticket balance at an EIP-6372 timepoint.
     * @dev The ticket token uses {block.timestamp} for its voting clock.
     * @param operator Address of the operator
     * @param timepoint Timestamp-mode checkpoint to query
     * @return Ticket balance at the specified timepoint
     */
    function getTicketBalanceAtBlock(
        address operator,
        uint256 timepoint
    ) external view returns (uint256);

    /**
     * @notice Get operator's total pending exit amounts
     * @param operator Address of the operator
     * @return ticket Total pending ticket balance in exit queue
     * @return ciphernodeBond Total pending ciphernode bond in exit queue
     */
    function pendingExits(
        address operator
    ) external view returns (uint256 ticket, uint256 ciphernodeBond);

    /**
     * @notice Preview how much an operator can currently claim
     * @param operator Address of the operator
     * @return ticket Claimable ticket balance
     * @return ciphernodeBond Claimable ciphernode bond
     */
    function previewClaimable(
        address operator
    ) external view returns (uint256 ticket, uint256 ciphernodeBond);

    /**
     * @notice Get slashed funds treasury address
     * @return Address where slashed funds are sent
     */
    function slashedFundsTreasury() external view returns (address);

    /**
     * @notice Get total slashed ticket balance
     * @return Amount of ticket balance slashed and available for treasury withdrawal
     */
    function slashedTicketBalance() external view returns (uint256);

    /// @notice Get slashed ticket funds reserved for retryable E3 routing.
    function reservedSlashedTicketBalance() external view returns (uint256);

    /// @notice Return one proposal-scoped slashed-ticket reservation.
    function getSlashedTicketReservation(
        address manager,
        uint256 proposalId
    )
        external
        view
        returns (uint256 e3Id, address refundManager, uint256 amount);

    /// @notice Return the number of pending slash routes owned by a manager.
    function pendingSlashRouteCount(
        address manager
    ) external view returns (uint256 count);

    /// @notice Get the ticket wrapper whose underlying asset backs ticket slashes.
    function ticketToken() external view returns (InterfoldTicketToken);

    /**
     * @notice Get total slashed ciphernode bond
     * @return Amount of ciphernode bond slashed and available for treasury withdrawal
     */
    function slashedCiphernodeBond() external view returns (uint256);

    // ======================
    // Operator Functions
    // ======================

    /**
     * @notice Register an operator whose collateral is controlled by the caller.
     */
    function registerOperatorFor(address operator) external;

    /**
     * @notice Deregister an operator.
     * @dev Callable by the bond owner or by the operator as an emergency kill switch.
     */
    function deregisterOperatorFor(address operator) external;

    /**
     * @notice Increase an operator's ticket balance using the bond owner's funds.
     */
    function addTicketBalanceFor(address operator, uint256 amount) external;

    /**
     * @notice Queue ticket collateral owned by the caller for withdrawal.
     */
    function removeTicketBalanceFor(address operator, uint256 amount) external;

    /**
     * @notice Bond collateral for an operator using the bond owner's funds.
     */
    function bondCiphernodeFor(address operator, uint256 amount) external;

    /**
     * @notice Queue ciphernode bond collateral owned by the caller for withdrawal.
     */
    function unbondCiphernodeFor(address operator, uint256 amount) external;

    /**
     * @notice Authorize a bond owner for the caller's operator key.
     * @dev The owner may be the operator itself. The operator may correct this
     *      choice while the position is empty; funded positions require current-owner
     *      proposal and new-owner acceptance.
     */
    function setBondOwner(address bondOwner) external;

    /**
     * @notice Propose transferring an operator position to a new bond owner.
     * @dev Only the current bond owner may propose or replace a pending transfer.
     */
    function proposeBondOwner(address operator, address newOwner) external;

    /**
     * @notice Accept a proposed operator position from its current bond owner.
     * @dev Moves ownership accounting for active and pending ciphernode bond collateral
     *      only when doing so preserves the previous owner's locked-FOLD coverage.
     */
    function acceptBondOwner(address operator) external;

    // ======================
    // Claim Functions
    // ======================

    /**
     * @notice Claim matured exits to an operator's bond owner.
     * @dev Anyone may settle tickets. Only the bond owner may settle ciphernode bonds.
     */
    function claimExitsFor(
        address operator,
        uint256 maxTicketAmount,
        uint256 maxCiphernodeBondAmount
    ) external;

    /// @notice Snapshot, open, or release an E3's committee obligations.
    /// @dev The current registry snapshots ownership with a zero-address active update.
    ///      Only that request-time registry may make later updates for the E3.
    function setCommitteeObligation(
        uint256 e3Id,
        address operator,
        bool active
    ) external;

    // ======================
    // Slashing Functions
    // ======================

    /**
     * @notice Slash operator's ticket balance by absolute amount
     * @param operator Address of the operator to slash
     * @param amount Amount to slash
     * @param reason Reason for slashing (stored in event)
     * @dev Only callable by authorized slashing manager
     */
    function slashTicketBalance(
        address operator,
        uint256 amount,
        bytes32 reason
    ) external returns (uint256 actualAmount);

    /**
     * @notice Slash operator's ciphernode bond by absolute amount
     * @param operator Address of the operator to slash
     * @param amount Amount to slash
     * @param reason Reason for slashing (stored in event)
     * @dev Only callable by authorized slashing manager
     * @return actualAmount Amount removed from active and pending ciphernode bond collateral
     */
    function slashCiphernodeBond(
        address operator,
        uint256 amount,
        bytes32 reason
    ) external returns (uint256 actualAmount);

    /// @notice Freeze the refund manager used by this manager and E3.
    /// @dev The authorized slashing manager calls this during E3 setup.
    function snapshotSlashRouteDestination(
        uint256 e3Id,
        address refundManager,
        address interfold
    ) external;

    /// @notice Release one terminal E3 assignment from its manager.
    function releaseSlashRouteDestination(uint256 e3Id) external;

    /// @notice Record one proposal-scoped collateral lock.
    function openSlashLock(
        uint256 e3Id,
        uint256 proposalId,
        address operator
    ) external;

    /// @notice Close one proposal-scoped collateral lock.
    function closeSlashLock(uint256 proposalId, address operator) external;

    /// @notice Set this manager's ban state for an operator.
    function setOperatorBan(address operator, bool banned) external;

    /// @notice Deliberately clear one retained manager's ban.
    function clearSlashingManagerBan(
        address manager,
        address operator
    ) external;

    /// @notice Reserve slashed ticket funds for one proposal.
    function reserveSlashedTicketFunds(
        uint256 proposalId,
        uint256 e3Id,
        uint256 amount
    ) external;

    /// @notice Route one proposal's full reservation to its frozen refund manager.
    function redirectReservedSlashedTicketFunds(uint256 proposalId) external;

    // ======================
    // Reward Distribution Functions
    // ======================
    /**
     * @notice Distribute rewards for operators to their configured bond owners.
     * @param rewardToken Reward token contract
     * @param operators Addresses of the operators to distribute rewards to
     * @param amounts Amounts of rewards to distribute to each operator
     * @dev Falls back to the supplied address when it has no configured bond owner.
     *      Only callable by authorized distributors.
     */
    function distributeRewards(
        IERC20 rewardToken,
        address[] calldata operators,
        uint256[] calldata amounts
    ) external;

    // ======================
    // Admin Functions
    // ======================

    /// @notice Sets both bonding tokens and their raw-unit values atomically.
    /// @dev Both underlying assets must transfer exact amounts and must not
    ///      rebase account balances. Before validation, any old ciphernode-bond
    ///      balance above recorded liabilities is sent to the treasury in this
    ///      same transaction.
    function setBondingAssetConfig(BondingAssetConfig calldata config) external;

    /**
     * @notice Set ciphernode bond active BPS
     * @param newBps New ciphernode bond active BPS
     * @dev Only callable by contract owner. Invalidates cached operator status.
     */
    function setCiphernodeBondActiveBps(uint256 newBps) external;

    /**
     * @notice Set minimum ticket balance required for activation
     * @param newMinTicketBalance New minimum ticket balance
     * @dev Only callable by contract owner. Invalidates cached operator status.
     */
    function setMinTicketBalance(uint256 newMinTicketBalance) external;

    /**
     * @notice Set exit delay period
     * @param newExitDelay New exit delay in seconds
     * @dev Only callable by contract owner. The delay must exceed the
     *      configured registry's exit-delay floor.
     */
    function setExitDelay(uint64 newExitDelay) external;

    /**
     * @notice Send unaccounted ciphernode-bond-token surplus to the slashed-funds treasury.
     * @dev Never transfers active bonds, queued exits, or slashed-fund liabilities.
     *      {setBondingAssetConfig} invokes the same cleanup automatically.
     * @return amount Amount requested for transfer
     */
    function sweepCiphernodeBondSurplus() external returns (uint256 amount);

    /**
     * @notice Set slashed funds treasury address
     * @param newSlashedFundsTreasury New slashed funds treasury address
     * @dev Only callable by contract owner
     */
    function setSlashedFundsTreasury(address newSlashedFundsTreasury) external;

    /**
     * @notice Set registry address
     * @param newRegistry New registry contract address
     * @dev Only callable by contract owner. The address cannot be zero.
     */
    /// @dev The new registry's exit-delay floor must be shorter than {exitDelay}.
    function setRegistry(ICiphernodeRegistry newRegistry) external;

    /**
     * @notice Set slashing manager address
     * @param newSlashingManager New slashing manager contract address
     * @dev Only callable by contract owner
     */
    function setSlashingManager(address newSlashingManager) external;

    /**
     * @notice Revoke a non-current slashing manager after every E3 and proposal
     *         that depends on it has reached a terminal state.
     * @param oldSlashingManager Manager whose authority should be removed
     */
    function revokeSlashingManager(address oldSlashingManager) external;

    /**
     * @notice Whether a manager may slash collateral or route reserved slash funds.
     */
    function isAuthorizedSlashingManager(
        address candidate
    ) external view returns (bool);

    /**
     * @notice Number of currently authorized slashing managers.
     */
    function authorizedSlashingManagerCount() external view returns (uint256);

    /**
     * @notice Authorized slashing manager at `index`.
     */
    function authorizedSlashingManagerAt(
        uint256 index
    ) external view returns (address);

    /**
     * @notice Set reward distributor address
     * @param newRewardDistributor New reward distributor address
     * @dev Only callable by contract owner
     */
    function setRewardDistributor(address newRewardDistributor) external;

    /**
     * @notice Revoke reward distributor authorization
     * @param distributor Address to revoke
     * @dev Only callable by contract owner
     */
    function revokeRewardDistributor(address distributor) external;

    /**
     * @notice Withdraw slashed funds to treasury
     * @param ticketAmount Amount of slashed ticket balance to withdraw
     * @param ciphernodeBondAmount Amount of slashed ciphernode bond to withdraw
     * @dev Only callable by contract owner, sends to treasury address
     */
    function withdrawSlashedFunds(
        uint256 ticketAmount,
        uint256 ciphernodeBondAmount
    ) external;
}
