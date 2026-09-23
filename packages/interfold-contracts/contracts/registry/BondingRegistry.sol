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
    ReentrancyGuardUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { IBondedCheckpoints } from "../interfaces/IBondedCheckpoints.sol";
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { BondingAssetLib } from "../lib/BondingAssetLib.sol";
import { BondingEligibilityLib } from "../lib/BondingEligibilityLib.sol";
import { BondingSlashingLib } from "../lib/BondingSlashingLib.sol";
import { BondingRegistrationLib } from "../lib/BondingRegistrationLib.sol";
import { BondingOwnershipLib } from "../lib/BondingOwnershipLib.sol";
import { ExitQueueLib } from "../lib/ExitQueueLib.sol";

import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { IBondOwnerHistory } from "../interfaces/IBondOwnerHistory.sol";
import {
    BondOwnerHistoryStorage
} from "../storage/BondOwnerHistoryStorage.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import {
    BondingEligibilityStorage
} from "../storage/BondingEligibilityStorage.sol";
import { BondingSlashingStorage } from "../storage/BondingSlashingStorage.sol";
import { InterfoldTicketToken } from "../token/InterfoldTicketToken.sol";

/**
 * @title BondingRegistry
 * @notice Implementation of the bonding registry managing operator ticket balances and ciphernode bonds
 * @dev Handles deposits, withdrawals, slashing, exits, and integrates with registry and slashing manager
 */
// solhint-disable-next-line max-states-count
contract BondingRegistry is
    IBondingRegistry,
    IBondOwnerHistory,
    BondOwnerHistoryStorage,
    BondingEligibilityStorage,
    BondingSlashingStorage,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;
    using ExitQueueLib for ExitQueueLib.ExitQueueState;

    struct SlashedTicketReservation {
        uint256 e3Id;
        address refundManager;
        uint256 amount;
    }

    // ======================
    // Constants
    // ======================

    /// @dev Reason code for ticket balance deposits
    bytes32 private constant REASON_DEPOSIT = bytes32("DEPOSIT");

    /// @dev Reason code for ticket balance withdrawals
    bytes32 private constant REASON_WITHDRAW = bytes32("WITHDRAW");

    /// @dev Reason code for ciphernode bond operations
    bytes32 private constant REASON_BOND = bytes32("BOND");

    /// @dev Reason code for ciphernode bond unbond operations
    bytes32 private constant REASON_UNBOND = bytes32("UNBOND");

    // ======================
    // Storage
    // ======================

    /// @notice Ticket token (tFOLD with underlying USDC) used for collateral
    InterfoldTicketToken public ticketToken;

    /// @notice Ciphernode bond token (FOLD) required for operator registration
    IERC20 public ciphernodeBondToken;

    /// @notice Registry contract for managing committee membership
    ICiphernodeRegistry public registry;

    /// @notice Address authorized to perform slashing operations
    address public slashingManager;

    /// @notice Addresses authorized to distribute rewards to operators
    /// @dev Multiple contracts (Interfold, E3RefundManager) need to distribute rewards.
    ///      Each authorized distributor must approve this contract for the reward token.
    mapping(address distributor => bool authorized)
        public authorizedDistributors;

    /// @notice Current count of authorized distributors. Bounded by
    ///         {MAX_AUTHORIZED_DISTRIBUTORS}.
    uint256 public authorizedDistributorCount;

    /// @notice Hard cap on the number of authorized reward distributors so
    ///         downstream payout loops stay bounded.
    uint256 public constant MAX_AUTHORIZED_DISTRIBUTORS = 32;

    /// @notice Minimum permitted value for {exitDelay}. Set to one day so
    ///         an attacker cannot drain stake immediately after winning ownership.
    uint64 public constant MIN_EXIT_DELAY = 1 days;

    /// @notice Maximum permitted value for {exitDelay}. Caps the freeze
    ///         duration so operators retain a meaningful exit path.
    uint64 public constant MAX_EXIT_DELAY = 90 days; // duration in seconds; not calendar-aware

    /// @notice Basis-points denominator (100% = 10_000 bps).
    uint256 internal constant BPS_BASE = 10_000;

    /// @notice Treasury address that receives slashed funds
    address public slashedFundsTreasury;

    /// @notice Price per ticket in ticket token units
    uint256 public ticketPrice;

    /// @notice Minimum ciphernode bond required for initial registration
    uint256 public requiredCiphernodeBond;

    /// @notice Minimum number of tickets required to maintain active status
    uint256 public minTicketBalance;

    /// @notice Time delay in seconds before exits can be claimed
    uint64 public exitDelay;

    /// @notice Percentage (in basis points) of ciphernode bond that must remain bonded to stay active
    /// @dev Default 8000 = 80%. Allows operators to unbond up to 20% while remaining active
    uint256 public ciphernodeBondActiveBps;

    /// @notice Number of currently active operators
    uint256 public numActiveOperators;

    /// @notice Operator state data structure
    /// @param ciphernodeBond Amount of ciphernode bond tokens currently bonded
    /// @param exitUnlocksAt Timestamp when pending exit can be claimed
    /// @param registered Whether operator is registered in the protocol
    /// @param exitRequested Whether operator has requested to exit
    /// @param active Whether operator meets all requirements for active status
    struct Operator {
        uint256 ciphernodeBond;
        uint64 exitUnlocksAt;
        bool registered;
        bool exitRequested;
        bool active;
        uint256 eligibilityVersion;
    }

    /// @notice Maps operator address to their state data
    mapping(address operator => Operator data) internal operators;

    /// @notice Total slashed ticket balance available for treasury withdrawal
    uint256 public slashedTicketBalance;

    /// @notice Total slashed ciphernode bond available for treasury withdrawal
    uint256 public slashedCiphernodeBond;

    // ======================
    // Exit Queue library state
    // ======================

    /// @dev Internal state for managing exit queue of tickets and ciphernode bonds
    ExitQueueLib.ExitQueueState private _exits;

    /// @notice Version of the current operator-eligibility policy.
    /// @dev Every eligibility update advances the version and resets
    ///      {numActiveOperators}. Operators fail closed until refreshed.
    uint256 public eligibilityConfigurationVersion;

    /// @notice Slashed tickets committed to retryable E3 refund routes.
    uint256 public reservedSlashedTicketBalance;

    /// @notice Slashing managers that may finish snapshotted E3 lifecycles.
    /// @dev Rotating the current manager does not revoke its predecessor.
    address[] internal _authorizedSlashingManagers;

    /// @dev One-based index into {_authorizedSlashingManagers}; zero means unauthorized.
    mapping(address manager => uint256 indexPlusOne)
        internal _authorizedSlashingManagerIndex;

    /// @notice Maximum number of concurrently authorized slashing managers.
    uint256 public constant MAX_AUTHORIZED_SLASHING_MANAGERS = 32;

    /// @inheritdoc IBondingRegistry
    uint256 public totalCiphernodeBondLiability;

    /// @dev Owner authorized by an operator. Zero means unset.
    mapping(address operator => address bondOwner) private _bondOwnerOf;

    /// @dev Aggregate ciphernode bond collateral owned by an account across operator keys.
    mapping(address bondOwner => uint256 amount) private _bondedByOwner;

    /// @dev Proposed owner in the two-step bond-owner transfer flow.
    mapping(address operator => address pendingOwner)
        private _pendingBondOwnerOf;

    /// @dev Refund manager frozen by each slashing manager for each E3.
    mapping(address manager => mapping(uint256 e3Id => address refundManager))
        private _slashRouteDestinations;

    /// @dev Proposal-scoped reservations owned by each slashing manager.
    mapping(address manager => mapping(uint256 proposalId => SlashedTicketReservation reservation))
        private _slashedTicketReservations;

    /// @dev Number of proposal-scoped reservations owned by each manager.
    mapping(address manager => uint256 count) private _pendingSlashRouteCount;

    /// @notice Version shared by the ticket and ciphernode bond asset identities.
    uint64 public bondingAssetConfigurationVersion;

    /// @notice Expected decimals for the active ticket token.
    uint8 private _ticketTokenDecimals;

    /// @notice Expected decimals for the active ciphernode bond token.
    uint8 private _ciphernodeBondTokenDecimals;

    /// @inheritdoc IBondingRegistry
    uint256 public numRegisteredOperators;

    // ======================
    // Modifiers
    // ======================

    /// @dev Restricts function access to current or retained historical managers.
    modifier onlyAuthorizedSlashingManager() {
        if (_authorizedSlashingManagerIndex[msg.sender] == 0) {
            revert Unauthorized();
        }
        _;
    }

    /// @dev Restricts function access to authorized reward distributors
    modifier onlyAuthorizedDistributor() {
        require(authorizedDistributors[msg.sender], OnlyRewardDistributor());
        _;
    }

    /// @dev Reverts if operator has an exit in progress that hasn't unlocked yet
    /// @param operator Address of the operator to check
    modifier noExitInProgress(address operator) {
        Operator memory op = operators[operator];
        if (op.exitRequested && block.timestamp < op.exitUnlocksAt) {
            revert ExitInProgress();
        }
        _;
    }

    /// @dev Keeps active and already-queued collateral available while any
    ///      financial slash proposal against the operator is unresolved.
    modifier noOpenSlashProposal(address operator) {
        if (BondingSlashingLib.openSlashLockCount(operator) != 0) {
            revert OperatorUnderSlash();
        }
        _;
    }

    /// @dev Restricts collateral and lifecycle actions to the operator's bond owner.
    modifier onlyBondOwner(address operator) {
        _checkBondOwner(operator);
        _;
    }

    /// @dev Allows the collateral owner or the hot operator key to stop participation.
    modifier onlyBondOwnerOrOperator(address operator) {
        if (msg.sender != operator) {
            _checkBondOwner(operator);
        }
        _;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Initialization                       //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Locks the implementation; initialize via the proxy.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the bonding registry contract
    /// @param _owner Address that will own the contract
    /// @param assetConfig Bonding tokens and their raw-unit values
    /// @param _registry Ciphernode registry contract
    /// @param _slashedFundsTreasury Address to receive slashed funds
    /// @param _minTicketBalance Initial minimum ticket balance for activation
    /// @param _exitDelay Initial exit delay period in seconds
    function initialize(
        address _owner,
        BondingAssetConfig calldata assetConfig,
        ICiphernodeRegistry _registry,
        address _slashedFundsTreasury,
        uint256 _minTicketBalance,
        uint64 _exitDelay
    ) public initializer {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        _setBondingAssetConfig(assetConfig);
        setRegistry(_registry);
        setSlashedFundsTreasury(_slashedFundsTreasury);
        setMinTicketBalance(_minTicketBalance);
        setExitDelay(_exitDelay);
        setCiphernodeBondActiveBps(8_000);
        if (_owner != owner()) _transferOwnership(_owner);
    }

    // ======================
    // View Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function getCiphernodeBondToken() external view returns (address) {
        return address(ciphernodeBondToken);
    }

    /// @inheritdoc IBondingRegistry
    function getTicketToken() external view returns (address) {
        return address(ticketToken);
    }

    /// @inheritdoc IBondingRegistry
    function getTicketBalance(
        address operator
    ) external view returns (uint256) {
        return BondingAssetLib.ticketBalance(address(ticketToken), operator);
    }

    /// @inheritdoc IBondingRegistry
    function getCiphernodeBond(
        address operator
    ) external view returns (uint256) {
        return operators[operator].ciphernodeBond;
    }

    /// @inheritdoc IBondingRegistry
    function bondOwnerOf(address operator) public view returns (address) {
        return _bondOwnerOf[operator];
    }

    /// @inheritdoc IBondOwnerHistory
    function bondOwnerAt(
        address operator,
        uint256 timepoint
    ) external view returns (address) {
        return
            BondingOwnershipLib.bondOwnerAt(_bondOwnerOf, operator, timepoint);
    }

    /// @inheritdoc IBondingRegistry
    function pendingBondOwnerOf(
        address operator
    ) external view returns (address) {
        return _pendingBondOwnerOf[operator];
    }

    /// @inheritdoc IBondingRegistry
    function totalBonded(address account) external view returns (uint256) {
        return _bondedByOwner[account];
    }

    /// @inheritdoc IBondingRegistry
    function availableTickets(
        address operator
    ) external view returns (uint256) {
        return
            BondingAssetLib.availableTickets(
                address(ticketToken),
                operator,
                ticketPrice
            );
    }

    /// @inheritdoc IBondingRegistry
    function getTicketBalanceAtBlock(
        address operator,
        uint256 timepoint
    ) external view returns (uint256) {
        return
            BondingAssetLib.ticketBalanceAt(
                address(ticketToken),
                operator,
                timepoint
            );
    }

    /// @notice Get operator's total pending exit amounts
    /// @param operator Address of the operator
    /// @return ticket Total pending ticket balance in exit queue
    /// @return ciphernodeBond Total pending ciphernode bond in exit queue
    function pendingExits(
        address operator
    ) external view returns (uint256 ticket, uint256 ciphernodeBond) {
        (ticket, ciphernodeBond) = _exits.getPendingAmounts(operator);
    }

    /// @notice Preview how much an operator can currently claim
    /// @param operator Address of the operator
    /// @return ticket Claimable ticket balance
    /// @return ciphernodeBond Claimable ciphernode bond
    function previewClaimable(
        address operator
    ) external view returns (uint256 ticket, uint256 ciphernodeBond) {
        (ticket, ciphernodeBond) = _exits.previewClaimableAmounts(operator);
    }

    /// @inheritdoc IBondingRegistry
    function isCiphernodeBonded(address operator) external view returns (bool) {
        return
            BondingEligibilityLib.isCiphernodeBonded(
                operators[operator].ciphernodeBond,
                requiredCiphernodeBond,
                ciphernodeBondActiveBps
            );
    }

    /// @inheritdoc IBondingRegistry
    function isRegistered(address operator) external view returns (bool) {
        return operators[operator].registered;
    }

    /// @inheritdoc IBondingRegistry
    function isActive(address operator) external view returns (bool) {
        Operator storage op = operators[operator];
        return
            op.eligibilityVersion == eligibilityConfigurationVersion &&
            op.active;
    }

    /// @inheritdoc IBondingRegistry
    function eligibilityAt(
        address operator,
        uint256 timepoint
    ) external view returns (bool active, uint256 activeOperatorCount) {
        return BondingEligibilityLib.eligibilityAt(operator, timepoint);
    }

    /// @inheritdoc IBondingRegistry
    function refreshOperatorStatus(address operator) public {
        if (operator == address(0)) {
            BondingEligibilityLib.requireNodeReleaseRegistry(
                address(registry),
                msg.sender
            );
            _invalidateEligibilityStatuses();
            return;
        }
        require(operators[operator].registered, NotRegistered());
        _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function refreshOperatorStatuses(address[] calldata operatorList) external {
        uint256 len = operatorList.length;
        for (uint256 i = 0; i < len; ++i) {
            refreshOperatorStatus(operatorList[i]);
        }
    }

    /// @inheritdoc IBondingRegistry
    function hasExitInProgress(address operator) external view returns (bool) {
        Operator memory op = operators[operator];
        return op.exitRequested && block.timestamp < op.exitUnlocksAt;
    }

    /// @inheritdoc IBondingRegistry
    function isAuthorizedSlashingManager(
        address candidate
    ) external view returns (bool) {
        return _authorizedSlashingManagerIndex[candidate] != 0;
    }

    /// @inheritdoc IBondingRegistry
    function authorizedSlashingManagerCount() external view returns (uint256) {
        return _authorizedSlashingManagers.length;
    }

    /// @inheritdoc IBondingRegistry
    function authorizedSlashingManagerAt(
        uint256 index
    ) external view returns (address) {
        return _authorizedSlashingManagers[index];
    }

    /// @inheritdoc IBondingRegistry
    function getSlashedTicketReservation(
        address manager,
        uint256 proposalId
    )
        external
        view
        returns (uint256 e3Id, address refundManager, uint256 amount)
    {
        SlashedTicketReservation
            storage reservation = _slashedTicketReservations[manager][
                proposalId
            ];
        return (
            reservation.e3Id,
            reservation.refundManager,
            reservation.amount
        );
    }

    /// @inheritdoc IBondingRegistry
    function pendingSlashRouteCount(
        address manager
    ) external view returns (uint256) {
        return _pendingSlashRouteCount[manager];
    }

    /// @inheritdoc IBondingRegistry
    function unresolvedCommitteeCount() external view returns (uint256) {
        return BondingSlashingLib.unresolvedCommitteeCount();
    }

    // ======================
    // Operator Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function setBondOwner(address bondOwner) external {
        BondingOwnershipLib.setBondOwner(
            _bondOwnerOf,
            _pendingBondOwnerOf,
            operators,
            _exits,
            ticketToken,
            bondOwner
        );
    }

    /// @inheritdoc IBondingRegistry
    function proposeBondOwner(address operator, address newOwner) external {
        BondingOwnershipLib.proposeTransfer(
            _bondOwnerOf,
            _pendingBondOwnerOf,
            operator,
            newOwner
        );
    }

    /// @inheritdoc IBondingRegistry
    function acceptBondOwner(address operator) external {
        require(msg.sender == _pendingBondOwnerOf[operator], Unauthorized());

        address previousOwner = bondOwnerOf(operator);
        (, uint256 pendingCiphernodeBond) = _exits.getPendingAmounts(operator);
        uint256 delegatedBond = operators[operator].ciphernodeBond +
            pendingCiphernodeBond;

        if (delegatedBond != 0) {
            uint256 remainingBonded = _bondedByOwner[previousOwner] -
                delegatedBond;
            uint256 lockedBalance = BondingAssetLib.lockedBalanceOf(
                address(ciphernodeBondToken),
                previousOwner
            );
            uint256 controlledBalance = ciphernodeBondToken.balanceOf(
                previousOwner
            ) + remainingBonded;
            if (lockedBalance > controlledBalance) {
                revert BondOwnerTransferViolatesLock(
                    previousOwner,
                    lockedBalance,
                    controlledBalance
                );
            }
        }

        BondingOwnershipLib.completeTransfer(
            _bondOwnerOf,
            _pendingBondOwnerOf,
            _bondedByOwner,
            operator,
            delegatedBond
        );
        // Both sides, in the same call: the bond leaves one history and joins the other, and
        // checkpointing only the receiver would leave the previous owner voting with weight it
        // no longer holds.
        _syncBondedCheckpoint(previousOwner);
        _syncBondedCheckpoint(msg.sender);

        emit BondOwnerSet(operator, msg.sender);
    }

    /// @inheritdoc IBondingRegistry
    function registerOperatorFor(
        address operator
    ) external noExitInProgress(operator) onlyBondOwner(operator) {
        _registerOperator(operator);
    }

    function _registerOperator(address operator) internal {
        BondingRegistrationLib.register(
            operators,
            operator,
            slashingManager,
            requiredCiphernodeBond,
            _isOperatorBanned(operator)
        );
        // Counted here, before the external call, exactly as before the extraction: the counter
        // is a scalar the library cannot reach, and incrementing it afterwards would leave a
        // window where the operator reads as registered but uncounted.
        numRegisteredOperators++;

        // CiphernodeRegistry already emits an event when a ciphernode is added
        registry.addCiphernode(operator);

        _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function deregisterOperatorFor(
        address operator
    )
        external
        noExitInProgress(operator)
        noOpenSlashProposal(operator)
        onlyBondOwnerOrOperator(operator)
    {
        _deregisterOperator(operator);
    }

    function _deregisterOperator(address operator) internal {
        uint64 exitUnlocksAt = BondingRegistrationLib.markDeregistered(
            operators,
            operator,
            exitDelay
        );
        // Decremented between the two library calls, which is where the original decrements it:
        // before any token call, so no external callee observes a deregistered operator that is
        // still counted.
        numRegisteredOperators--;

        BondingRegistrationLib.releaseAssets(
            operators,
            _exits,
            ticketToken,
            operator,
            exitDelay
        );

        // CiphernodeRegistry already emits an event when a ciphernode is removed
        registry.removeCiphernode(operator);

        emit CiphernodeDeregistrationRequested(operator, exitUnlocksAt);
        _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function addTicketBalanceFor(
        address operator,
        uint256 amount
    ) external noExitInProgress(operator) onlyBondOwner(operator) {
        _addTicketBalance(operator, amount);
    }

    function _addTicketBalance(address operator, uint256 amount) internal {
        require(amount != 0, ZeroAmount());
        require(operators[operator].registered, NotRegistered());

        ticketToken.depositFrom(msg.sender, operator, amount);

        emit TicketBalanceUpdated(
            operator,
            int256(amount),
            ticketToken.balanceOf(operator),
            REASON_DEPOSIT
        );

        _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function removeTicketBalanceFor(
        address operator,
        uint256 amount
    )
        external
        noExitInProgress(operator)
        noOpenSlashProposal(operator)
        onlyBondOwner(operator)
    {
        _removeTicketBalance(operator, amount);
    }

    function _removeTicketBalance(address operator, uint256 amount) internal {
        require(amount != 0, ZeroAmount());
        require(operators[operator].registered, NotRegistered());
        require(
            ticketToken.balanceOf(operator) >= amount,
            InsufficientBalance()
        );

        ticketToken.burnTickets(operator, amount);
        _exits.queueTicketsForExit(operator, exitDelay, amount);

        emit TicketBalanceUpdated(
            operator,
            -int256(amount),
            ticketToken.balanceOf(operator),
            REASON_WITHDRAW
        );

        _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function bondCiphernodeFor(
        address operator,
        uint256 amount
    ) external nonReentrant noExitInProgress(operator) {
        _bondCiphernode(operator, amount);
    }

    /// @inheritdoc IBondingRegistry
    function unbondCiphernodeFor(
        address operator,
        uint256 amount
    )
        external
        nonReentrant
        noExitInProgress(operator)
        noOpenSlashProposal(operator)
        onlyBondOwner(operator)
    {
        _unbondCiphernode(operator, amount);
    }

    function _unbondCiphernode(address operator, uint256 amount) internal {
        require(amount != 0, ZeroAmount());
        require(
            operators[operator].ciphernodeBond >= amount,
            InsufficientBalance()
        );

        operators[operator].ciphernodeBond -= amount;
        _exits.queueCiphernodeBondsForExit(operator, exitDelay, amount);

        emit CiphernodeBondUpdated(
            operator,
            -int256(amount),
            operators[operator].ciphernodeBond,
            REASON_UNBOND
        );

        _updateOperatorStatus(operator);
    }

    // ======================
    // Claim Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function claimExitsFor(
        address operator,
        uint256 maxTicketAmount,
        uint256 maxCiphernodeBondAmount
    ) external nonReentrant {
        if (maxCiphernodeBondAmount != 0) _checkBondOwner(operator);
        BondingSlashingLib.validateExitClaim(operator);
        _claimExits(operator, maxTicketAmount, maxCiphernodeBondAmount);
    }

    /// @inheritdoc IBondingRegistry
    function setCommitteeObligation(
        uint256 e3Id,
        address operator,
        bool active
    ) external {
        BondingSlashingLib.setCommitteeObligation(
            address(registry),
            e3Id,
            operator,
            active
        );
    }

    function _claimExits(
        address operator,
        uint256 maxTicketAmount,
        uint256 maxCiphernodeBondAmount
    ) internal {
        uint256 ciphernodeBondClaim = BondingAssetLib.claimExits(
            _exits,
            ticketToken,
            ciphernodeBondToken,
            _bondOwnerOf,
            _bondedByOwner,
            operator,
            maxTicketAmount,
            maxCiphernodeBondAmount
        );
        totalCiphernodeBondLiability -= ciphernodeBondClaim;
        // `BondingAssetLib.claimExits` decrements `_bondedByOwner` through a storage pointer, so
        // the checkpoint has to be taken here rather than at the write.
        _syncBondedCheckpoint(bondOwnerOf(operator));
    }

    // ======================
    // Slashing Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function slashTicketBalance(
        address operator,
        uint256 requestedSlashAmount,
        bytes32 slashReason
    ) external onlyAuthorizedSlashingManager returns (uint256) {
        require(requestedSlashAmount != 0, ZeroAmount());

        (uint256 pendingTicketBalance, ) = _exits.getPendingAmounts(operator);
        uint256 activeBalance = ticketToken.balanceOf(operator);
        uint256 totalAvailableBalance = activeBalance + pendingTicketBalance;

        uint256 actualSlashAmount = Math.min(
            requestedSlashAmount,
            totalAvailableBalance
        );

        if (actualSlashAmount == 0) {
            return 0;
        }

        // Slash from active balance first
        uint256 slashedFromActiveBalance = Math.min(
            actualSlashAmount,
            activeBalance
        );
        if (slashedFromActiveBalance > 0) {
            ticketToken.burnTickets(operator, slashedFromActiveBalance);
        }

        // Slash remaining amount from pending queue
        uint256 remainingToSlash = actualSlashAmount - slashedFromActiveBalance;
        if (remainingToSlash > 0) {
            (uint256 pendingSlashed, ) = _exits.slashPendingAssets(
                operator,
                remainingToSlash,
                0, // ciphernodeBondAmount
                true
            );
            require(pendingSlashed == remainingToSlash, InsufficientBalance());
        }

        slashedTicketBalance += actualSlashAmount;
        emit TicketBalanceUpdated(
            operator,
            -int256(actualSlashAmount),
            ticketToken.balanceOf(operator),
            slashReason
        );

        _updateOperatorStatus(operator);

        return actualSlashAmount;
    }

    /// @inheritdoc IBondingRegistry
    function slashCiphernodeBond(
        address operator,
        uint256 requestedSlashAmount,
        bytes32 slashReason
    ) external onlyAuthorizedSlashingManager nonReentrant returns (uint256) {
        require(requestedSlashAmount != 0, ZeroAmount());

        Operator storage operatorData = operators[operator];
        (, uint256 pendingCiphernodeBondBalance) = _exits.getPendingAmounts(
            operator
        );
        uint256 totalAvailableBalance = operatorData.ciphernodeBond +
            pendingCiphernodeBondBalance;
        uint256 actualSlashAmount = Math.min(
            requestedSlashAmount,
            totalAvailableBalance
        );

        if (actualSlashAmount == 0) return 0;

        uint256 activeSlashAmount = Math.min(
            actualSlashAmount,
            operatorData.ciphernodeBond
        );
        if (activeSlashAmount != 0) {
            operatorData.ciphernodeBond -= activeSlashAmount;
        }

        uint256 remainingSlashAmount = actualSlashAmount - activeSlashAmount;
        if (remainingSlashAmount != 0) {
            (, uint256 pendingSlashed) = _exits.slashPendingAssets(
                operator,
                0,
                remainingSlashAmount,
                true
            );
            require(
                pendingSlashed == remainingSlashAmount,
                InsufficientBalance()
            );
        }

        address bondOwner = bondOwnerOf(operator);
        _bondedByOwner[bondOwner] -= actualSlashAmount;
        _syncBondedCheckpoint(bondOwner);
        slashedCiphernodeBond += actualSlashAmount;
        emit CiphernodeBondUpdated(
            operator,
            -int256(actualSlashAmount),
            operatorData.ciphernodeBond,
            slashReason
        );

        _updateOperatorStatus(operator);
        return actualSlashAmount;
    }

    /// @inheritdoc IBondingRegistry
    function snapshotSlashRouteDestination(
        uint256 e3Id,
        address refundManager,
        address interfold
    ) external onlyAuthorizedSlashingManager {
        BondingSlashingLib.snapshotE3(
            msg.sender,
            e3Id,
            refundManager,
            interfold,
            _slashRouteDestinations
        );
    }

    /// @inheritdoc IBondingRegistry
    function releaseSlashRouteDestination(
        uint256 e3Id
    ) external onlyAuthorizedSlashingManager {
        BondingSlashingLib.releaseE3(msg.sender, e3Id, _slashRouteDestinations);
    }

    /// @inheritdoc IBondingRegistry
    function openSlashLock(
        uint256 e3Id,
        uint256 proposalId,
        address operator
    ) external onlyAuthorizedSlashingManager {
        BondingSlashingLib.openLock(
            msg.sender,
            e3Id,
            proposalId,
            operator,
            _slashRouteDestinations
        );
    }

    /// @inheritdoc IBondingRegistry
    function closeSlashLock(
        uint256 proposalId,
        address operator
    ) external onlyAuthorizedSlashingManager {
        BondingSlashingLib.closeLock(msg.sender, proposalId, operator);
    }

    /// @inheritdoc IBondingRegistry
    function setOperatorBan(
        address operator,
        bool banned
    ) external onlyAuthorizedSlashingManager {
        if (
            BondingSlashingLib.setBan(msg.sender, operator, banned) &&
            operators[operator].registered
        ) _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function clearSlashingManagerBan(
        address manager,
        address operator
    ) external onlyOwner {
        require(manager != slashingManager, InvalidConfiguration());
        if (_authorizedSlashingManagerIndex[manager] == 0) {
            revert Unauthorized();
        }
        if (
            BondingSlashingLib.setBan(manager, operator, false) &&
            operators[operator].registered
        ) _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function reserveSlashedTicketFunds(
        uint256 proposalId,
        uint256 e3Id,
        uint256 amount
    ) external onlyAuthorizedSlashingManager {
        require(amount > 0, ZeroAmount());
        address refundManager = _slashRouteDestinations[msg.sender][e3Id];
        if (refundManager == address(0)) {
            revert SlashRouteDestinationNotFound(msg.sender, e3Id);
        }
        if (_slashedTicketReservations[msg.sender][proposalId].amount != 0) {
            revert SlashReservationAlreadyExists(msg.sender, proposalId);
        }
        require(
            amount <= slashedTicketBalance - reservedSlashedTicketBalance,
            InsufficientBalance()
        );
        _slashedTicketReservations[msg.sender][
            proposalId
        ] = SlashedTicketReservation({
            e3Id: e3Id,
            refundManager: refundManager,
            amount: amount
        });
        _pendingSlashRouteCount[msg.sender]++;
        BondingSlashingLib.updateRouteCount(msg.sender, e3Id, true);
        reservedSlashedTicketBalance += amount;
        emit SlashedTicketFundsReserved(
            msg.sender,
            proposalId,
            e3Id,
            refundManager,
            amount
        );
    }

    /// @inheritdoc IBondingRegistry
    function redirectReservedSlashedTicketFunds(
        uint256 proposalId
    ) external onlyAuthorizedSlashingManager {
        SlashedTicketReservation
            memory reservation = _slashedTicketReservations[msg.sender][
                proposalId
            ];
        if (reservation.amount == 0) {
            revert SlashReservationNotFound(msg.sender, proposalId);
        }

        delete _slashedTicketReservations[msg.sender][proposalId];
        _pendingSlashRouteCount[msg.sender]--;
        BondingSlashingLib.updateRouteCount(
            msg.sender,
            reservation.e3Id,
            false
        );
        reservedSlashedTicketBalance -= reservation.amount;
        slashedTicketBalance -= reservation.amount;
        ticketToken.payout(reservation.refundManager, reservation.amount);
        emit ReservedSlashedTicketFundsRouted(
            msg.sender,
            proposalId,
            reservation.refundManager,
            reservation.amount
        );
    }

    // ======================
    // Reward Distribution Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function distributeRewards(
        IERC20 rewardToken,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external onlyAuthorizedDistributor {
        BondingAssetLib.distributeRewards(
            rewardToken,
            _bondOwnerOf,
            msg.sender,
            recipients,
            amounts
        );
    }

    // ======================
    // Admin Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function setBondingAssetConfig(
        BondingAssetConfig calldata config
    ) external onlyOwner {
        _setBondingAssetConfig(config);
    }

    function _setBondingAssetConfig(
        BondingAssetConfig calldata config
    ) internal {
        _sweepCiphernodeBondSurplus();
        bool ciphernodeBondTokenChanged = address(ciphernodeBondToken) !=
            config.ciphernodeBondToken;
        bool assetChanged = BondingAssetLib.validateBondingAssetConfig(
            address(ticketToken),
            address(ciphernodeBondToken),
            _ticketTokenDecimals,
            _ciphernodeBondTokenDecimals,
            bondingAssetConfigurationVersion,
            address(this),
            config,
            _authorizedSlashingManagers,
            _pendingSlashRouteCount
        );

        ticketToken = InterfoldTicketToken(config.ticketToken);
        ciphernodeBondToken = IERC20(config.ciphernodeBondToken);
        ticketPrice = config.ticketPrice;
        requiredCiphernodeBond = config.requiredCiphernodeBond;
        _ticketTokenDecimals = config.expectedTicketDecimals;
        _ciphernodeBondTokenDecimals = config.expectedCiphernodeBondDecimals;
        if (assetChanged) bondingAssetConfigurationVersion++;
        if (
            ciphernodeBondTokenChanged &&
            address(bondedCheckpoints) != address(0)
        ) {
            // The recorded history counts ciphernode-bond-token units, and `BondedVotes` adds them to the
            // voting power of one fixed token. Bonds of a replacement token would enter the same
            // history and be counted as that token, so summed voting power could exceed its total
            // supply. Rotation already requires every old bond to be drained, so each owner's last
            // recorded total is zero: detaching freezes a settled history rather than truncating a
            // live one. Governance may then attach a checkpoint contract for the new token, and
            // the old contract keeps answering correctly for the timepoints it covers.
            emit BondedCheckpointsDetached(address(bondedCheckpoints));
            delete bondedCheckpoints;
        }
        _invalidateEligibilityStatuses();
    }

    /// @inheritdoc IBondingRegistry
    function setCiphernodeBondActiveBps(uint256 newBps) public onlyOwner {
        require(newBps > 0 && newBps <= BPS_BASE, InvalidConfiguration());

        uint256 oldValue = ciphernodeBondActiveBps;
        if (oldValue == newBps) return;
        ciphernodeBondActiveBps = newBps;
        _invalidateEligibilityStatuses();

        emit ConfigurationUpdated("ciphernodeBondActiveBps", oldValue, newBps);
    }

    /// @inheritdoc IBondingRegistry
    function setBondedCheckpoints(
        IBondedCheckpoints newCheckpoints
    ) external onlyOwner {
        // One-time: repointing would abandon the recorded history, and every past vote reading
        // through it would silently change answer.
        require(
            address(bondedCheckpoints) == address(0),
            InvalidConfiguration()
        );
        // Subsumes a zero-address check: a call to an address with no code returns nothing, so
        // decoding the result reverts.
        require(
            newCheckpoints.registry() == address(this),
            InvalidConfiguration()
        );

        bondedCheckpoints = newCheckpoints;

        // Exercise the write path before the one-shot slot is spent. `registry()` alone does not
        // establish it: other protocol contracts answer `registry()` with this address, so an
        // address mixed up with one of them passes that check and then reverts on every bond,
        // slash, exit claim and owner transfer, with the slot consumed and no way to correct it.
        // The probe writes the zero address, whose bonded total is always zero, so it leaves no
        // state any real owner can read.
        _syncBondedCheckpoint(address(0));

        emit BondedCheckpointsSet(address(newCheckpoints));
    }

    /// @inheritdoc IBondingRegistry
    function resyncBondedCheckpoint(address bondOwner) external {
        _syncBondedCheckpoint(bondOwner);
    }

    /// @inheritdoc IBondingRegistry
    function setMinTicketBalance(uint256 newMinTicketBalance) public onlyOwner {
        require(newMinTicketBalance != 0, InvalidConfiguration());
        uint256 oldValue = minTicketBalance;
        if (oldValue == newMinTicketBalance) return;
        minTicketBalance = newMinTicketBalance;
        _invalidateEligibilityStatuses();

        emit ConfigurationUpdated(
            "minTicketBalance",
            oldValue,
            newMinTicketBalance
        );
    }

    /// @inheritdoc IBondingRegistry
    function setExitDelay(uint64 newExitDelay) public onlyOwner {
        // bound the configurable exit delay so a malicious owner cannot
        // instantly drain operator stake (delay too short) or permanently
        // freeze withdrawals (delay too long).
        // Keep the bounds check compact because BondingRegistry is size-constrained.
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            if or(lt(newExitDelay, 86400), gt(newExitDelay, 7776000)) {
                mstore(0x00, 0x2b4d9a8c)
                mstore(0x20, newExitDelay)
                revert(0x1c, 0x24)
            }
        }
        BondingAssetLib.validateExitTiming(address(registry), newExitDelay);
        uint256 oldValue = uint256(exitDelay);
        exitDelay = newExitDelay;

        emit ConfigurationUpdated("exitDelay", oldValue, uint256(newExitDelay));
    }

    /// @inheritdoc IBondingRegistry
    function setSlashedFundsTreasury(
        address newSlashedFundsTreasury
    ) public onlyOwner {
        require(newSlashedFundsTreasury != address(0), ZeroAddress());
        slashedFundsTreasury = newSlashedFundsTreasury;
        emit SlashedFundsTreasurySet(newSlashedFundsTreasury);
    }

    /// @inheritdoc IBondingRegistry
    function sweepCiphernodeBondSurplus()
        external
        onlyOwner
        returns (uint256 amount)
    {
        return _sweepCiphernodeBondSurplus();
    }

    function _sweepCiphernodeBondSurplus() private returns (uint256 amount) {
        return
            BondingAssetLib.sweepCiphernodeBondSurplus(
                address(ciphernodeBondToken),
                address(this),
                slashedFundsTreasury,
                totalCiphernodeBondLiability
            );
    }

    /// @inheritdoc IBondingRegistry
    function setRegistry(ICiphernodeRegistry newRegistry) public onlyOwner {
        BondingAssetLib.validateRegistryUpdate(
            address(registry),
            address(newRegistry),
            exitDelay,
            numRegisteredOperators,
            numActiveOperators,
            BondingSlashingLib.unresolvedCommitteeCount()
        );
        registry = newRegistry;
        emit RegistrySet(address(newRegistry));
    }

    /// @inheritdoc IBondingRegistry
    function setSlashingManager(address newSlashingManager) public onlyOwner {
        require(newSlashingManager != address(0), ZeroAddress());
        BondingSlashingLib.authorizeManager(
            newSlashingManager,
            address(this),
            MAX_AUTHORIZED_SLASHING_MANAGERS,
            _authorizedSlashingManagers,
            _authorizedSlashingManagerIndex
        );
        address oldValue = slashingManager;
        slashingManager = newSlashingManager;
        emit SlashingManagerUpdated(oldValue, newSlashingManager);
    }

    /// @inheritdoc IBondingRegistry
    function revokeSlashingManager(
        address oldSlashingManager
    ) external onlyOwner {
        BondingSlashingLib.revokeManager(
            oldSlashingManager,
            slashingManager,
            _authorizedSlashingManagers,
            _authorizedSlashingManagerIndex,
            _pendingSlashRouteCount
        );
    }

    /// @notice Disabled. Reverts unconditionally.
    function renounceOwnership() public pure override {
        revert RenounceOwnershipDisabled();
    }

    /// @notice Authorizes an address to distribute rewards
    /// @dev Only callable by owner. Supports multiple authorized distributors (Interfold + E3RefundManager)
    /// @param newRewardDistributor Address to authorize as reward distributor
    function setRewardDistributor(
        address newRewardDistributor
    ) external onlyOwner {
        authorizedDistributorCount = BondingAssetLib.setRewardDistributor(
            authorizedDistributors,
            authorizedDistributorCount,
            MAX_AUTHORIZED_DISTRIBUTORS,
            newRewardDistributor,
            true
        );
    }

    /// @notice Revokes reward distributor authorization
    /// @dev Only callable by owner
    /// @param distributor Address to revoke
    function revokeRewardDistributor(address distributor) external onlyOwner {
        authorizedDistributorCount = BondingAssetLib.setRewardDistributor(
            authorizedDistributors,
            authorizedDistributorCount,
            MAX_AUTHORIZED_DISTRIBUTORS,
            distributor,
            false
        );
    }

    /// @inheritdoc IBondingRegistry
    function withdrawSlashedFunds(
        uint256 ticketAmount,
        uint256 ciphernodeBondAmount
    ) external onlyOwner {
        require(
            ticketAmount <= slashedTicketBalance - reservedSlashedTicketBalance,
            ReservedSlashedFunds()
        );
        require(
            ciphernodeBondAmount <= slashedCiphernodeBond,
            InsufficientBalance()
        );

        if (ticketAmount > 0) {
            slashedTicketBalance -= ticketAmount;
            ticketToken.payout(slashedFundsTreasury, ticketAmount);
        }

        if (ciphernodeBondAmount > 0) {
            slashedCiphernodeBond -= ciphernodeBondAmount;
            totalCiphernodeBondLiability -= ciphernodeBondAmount;
            BondingAssetLib.transferExact(
                address(ciphernodeBondToken),
                slashedFundsTreasury,
                ciphernodeBondAmount
            );
        }

        emit SlashedFundsWithdrawn(
            slashedFundsTreasury,
            ticketAmount,
            ciphernodeBondAmount
        );
    }

    // ======================
    // Internal Functions
    // ======================

    function _bondCiphernode(address operator, uint256 amount) internal {
        require(operator != address(0), ZeroAddress());
        require(amount != 0, ZeroAmount());

        address bondOwner = bondOwnerOf(operator);
        require(msg.sender == bondOwner, NotBondOwner(msg.sender, operator));

        operators[operator].ciphernodeBond += amount;
        _bondedByOwner[bondOwner] += amount;
        _syncBondedCheckpoint(bondOwner);
        BondingAssetLib.transferFromExact(
            address(ciphernodeBondToken),
            msg.sender,
            amount
        );
        totalCiphernodeBondLiability += amount;

        emit CiphernodeBondUpdated(
            operator,
            int256(amount),
            operators[operator].ciphernodeBond,
            REASON_BOND
        );

        _updateOperatorStatus(operator);
    }

    /// @dev Record the owner's current bonded total in the checkpoint contract.
    ///
    /// Sends the total rather than a delta, so the history mirrors this mapping. A mutation site
    /// that forgets to call this is then caught by comparing the two, whereas a delta-derived
    /// history would drift undetected — and it would drift in voting weight.
    ///
    /// Skipped while unconfigured. This contract is upgradeable, so an upgrade lands before the
    /// checkpoint contract can be pointed at it, and reverting in that window would freeze
    /// bonding, unbonding and slashing. History therefore begins at configuration rather than at
    /// upgrade, which is visible on chain and cannot be mistaken for a zero balance.
    function _syncBondedCheckpoint(address bondOwner) internal {
        IBondedCheckpoints checkpoints = bondedCheckpoints;
        if (address(checkpoints) == address(0)) return;

        checkpoints.sync(bondOwner, _bondedByOwner[bondOwner]);
    }

    function _checkBondOwner(address operator) internal view {
        if (msg.sender != bondOwnerOf(operator)) {
            revert NotBondOwner(msg.sender, operator);
        }
    }

    /// @dev Updates operator's active status based on current conditions
    /// @dev Operator is active if: registered, has minimum ciphernode bond, and has minimum tickets
    /// @param operator Address of the operator to update
    function _updateOperatorStatus(address operator) internal {
        Operator storage op = operators[operator];
        uint256 currentVersion = eligibilityConfigurationVersion;
        bool oldActiveStatus = op.eligibilityVersion == currentVersion &&
            op.active;
        (uint256 activeCount, bool newActiveStatus) = BondingEligibilityLib
            .updateOperator(
                operator,
                oldActiveStatus,
                BondingEligibilityLib.OperatorRequirements({
                    registered: op.registered,
                    banned: _isOperatorBanned(operator),
                    ciphernodeBond: op.ciphernodeBond,
                    requiredCiphernodeBond: requiredCiphernodeBond,
                    ciphernodeBondActiveBps: ciphernodeBondActiveBps,
                    registry: address(registry),
                    ticketToken: address(ticketToken),
                    ticketPrice: ticketPrice,
                    minTicketBalance: minTicketBalance
                }),
                currentVersion,
                numActiveOperators
            );
        op.eligibilityVersion = currentVersion;
        op.active = newActiveStatus;
        numActiveOperators = activeCount;
    }

    /// @dev A ban from any retained slashing manager removes network eligibility.
    function _isOperatorBanned(address operator) internal view returns (bool) {
        return BondingSlashingLib.activeBanCount(operator) != 0;
    }

    /// @dev Invalidates every cached active status in O(1). Operators are
    ///      considered inactive until they refresh under the new version.
    function _invalidateEligibilityStatuses() internal {
        eligibilityConfigurationVersion = BondingEligibilityLib
            .invalidateConfiguration(eligibilityConfigurationVersion);
        numActiveOperators = 0;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              ERC-165 Interface Detection               //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice ERC-165 interface detection. Advertises
    ///         {IBondingRegistry}, {IBondOwnerHistory}, and {IERC165}.
    function supportsInterface(
        bytes4 interfaceId
    ) external pure virtual returns (bool) {
        return
            interfaceId == type(IBondingRegistry).interfaceId ||
            interfaceId == type(IBondOwnerHistory).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }

    /// @inheritdoc IBondingRegistry
    /// @dev Held off this contract because it is within a few hundred bytes of the EIP-170 limit.
    /// Unset until configured, and writes are skipped while it is — see {_syncBondedCheckpoint}.
    /// Readable so a deployment can verify the wiring it just configured.
    IBondedCheckpoints public bondedCheckpoints;

    /// @dev Reserved storage slots for future upgrades.
    // solhint-disable-next-line var-name-mixedcase
    uint256[38] private __gap;
}
