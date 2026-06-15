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
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { ExitQueueLib } from "../lib/ExitQueueLib.sol";

import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";
import { InterfoldTicketToken } from "../token/InterfoldTicketToken.sol";

/**
 * @title BondingRegistry
 * @notice Implementation of the bonding registry managing operator ticket balances and license bonds
 * @dev Handles deposits, withdrawals, slashing, exits, and integrates with registry and slashing manager
 */
// solhint-disable-next-line max-states-count
contract BondingRegistry is
    IBondingRegistry,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;
    using ExitQueueLib for ExitQueueLib.ExitQueueState;

    // ======================
    // Constants
    // ======================

    /// @dev Reason code for ticket balance deposits
    bytes32 private constant REASON_DEPOSIT = bytes32("DEPOSIT");

    /// @dev Reason code for ticket balance withdrawals
    bytes32 private constant REASON_WITHDRAW = bytes32("WITHDRAW");

    /// @dev Reason code for license bond operations
    bytes32 private constant REASON_BOND = bytes32("BOND");

    /// @dev Reason code for license unbond operations
    bytes32 private constant REASON_UNBOND = bytes32("UNBOND");

    // ======================
    // Storage
    // ======================

    /// @notice Ticket token (ITK with underlying USDC) used for collateral
    InterfoldTicketToken public ticketToken;

    /// @notice License token (INTF) required for operator registration
    IERC20 public licenseToken;

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

    /// @notice Minimum license bond required for initial registration
    uint256 public licenseRequiredBond;

    /// @notice Minimum number of tickets required to maintain active status
    uint256 public minTicketBalance;

    /// @notice Time delay in seconds before exits can be claimed
    uint64 public exitDelay;

    /// @notice Percentage (in basis points) of license bond that must remain bonded to stay active
    /// @dev Default 8000 = 80%. Allows operators to unbond up to 20% while remaining active
    uint256 public licenseActiveBps;

    /// @notice Number of currently active operators
    uint256 public numActiveOperators;

    /// @notice Operator state data structure
    /// @param licenseBond Amount of license tokens currently bonded
    /// @param exitUnlocksAt Timestamp when pending exit can be claimed
    /// @param registered Whether operator is registered in the protocol
    /// @param exitRequested Whether operator has requested to exit
    /// @param active Whether operator meets all requirements for active status
    struct Operator {
        uint256 licenseBond;
        uint64 exitUnlocksAt;
        bool registered;
        bool exitRequested;
        bool active;
    }

    /// @notice Maps operator address to their state data
    mapping(address operator => Operator data) internal operators;

    /// @notice Total slashed ticket balance available for treasury withdrawal
    uint256 public slashedTicketBalance;

    /// @notice Total slashed license bond available for treasury withdrawal
    uint256 public slashedLicenseBond;

    // ======================
    // Exit Queue library state
    // ======================

    /// @dev Internal state for managing exit queue of tickets and licenses
    ExitQueueLib.ExitQueueState private _exits;

    // ======================
    // Modifiers
    // ======================

    /// @dev Restricts function access to only the slashing manager
    modifier onlySlashingManager() {
        if (msg.sender != slashingManager) revert Unauthorized();
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
    /// @param _ticketToken Ticket token contract for collateral
    /// @param _licenseToken License token contract for bonding
    /// @param _registry Ciphernode registry contract
    /// @param _slashedFundsTreasury Address to receive slashed funds
    /// @param _ticketPrice Initial price per ticket
    /// @param _licenseRequiredBond Initial required license bond for registration
    /// @param _minTicketBalance Initial minimum ticket balance for activation
    /// @param _exitDelay Initial exit delay period in seconds
    function initialize(
        address _owner,
        InterfoldTicketToken _ticketToken,
        IERC20 _licenseToken,
        ICiphernodeRegistry _registry,
        address _slashedFundsTreasury,
        uint256 _ticketPrice,
        uint256 _licenseRequiredBond,
        uint256 _minTicketBalance,
        uint64 _exitDelay
    ) public initializer {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        setTicketToken(_ticketToken);
        setLicenseToken(_licenseToken);
        setRegistry(_registry);
        setSlashedFundsTreasury(_slashedFundsTreasury);
        setTicketPrice(_ticketPrice);
        setLicenseRequiredBond(_licenseRequiredBond);
        setMinTicketBalance(_minTicketBalance);
        setExitDelay(_exitDelay);
        setLicenseActiveBps(8_000);
        if (_owner != owner()) _transferOwnership(_owner);
    }

    // ======================
    // View Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function getLicenseToken() external view returns (address) {
        return address(licenseToken);
    }

    /// @inheritdoc IBondingRegistry
    function getTicketToken() external view returns (address) {
        return address(ticketToken);
    }

    /// @inheritdoc IBondingRegistry
    function getTicketBalance(
        address operator
    ) external view returns (uint256) {
        return ticketToken.balanceOf(operator);
    }

    /// @inheritdoc IBondingRegistry
    function getLicenseBond(address operator) external view returns (uint256) {
        return operators[operator].licenseBond;
    }

    /// @inheritdoc IBondingRegistry
    function totalBonded(address account) external view returns (uint256) {
        (, uint256 pendingLicense) = _exits.getPendingAmounts(account);
        return operators[account].licenseBond + pendingLicense;
    }

    /// @inheritdoc IBondingRegistry
    function availableTickets(
        address operator
    ) external view returns (uint256) {
        return ticketToken.balanceOf(operator) / ticketPrice;
    }

    /// @notice Get operator's ticket balance at a specific timepoint (EIP-6372).
    /// @dev The ticket token uses {block.timestamp} (mode=timestamp) for its voting clock, so
    ///      `blockNumber` is in fact a unix timestamp. Name is preserved for storage/event
    ///      compatibility.
    /// @param operator Address of the operator
    /// @param blockNumber Timepoint (block.timestamp) to query
    /// @return Ticket balance at the specified timepoint
    function getTicketBalanceAtBlock(
        address operator,
        uint256 blockNumber
    ) external view returns (uint256) {
        return ticketToken.getPastVotes(operator, blockNumber);
    }

    /// @notice Get operator's total pending exit amounts
    /// @param operator Address of the operator
    /// @return ticket Total pending ticket balance in exit queue
    /// @return license Total pending license bond in exit queue
    function pendingExits(
        address operator
    ) external view returns (uint256 ticket, uint256 license) {
        (ticket, license) = _exits.getPendingAmounts(operator);
    }

    /// @notice Preview how much an operator can currently claim
    /// @param operator Address of the operator
    /// @return ticket Claimable ticket balance
    /// @return license Claimable license bond
    function previewClaimable(
        address operator
    ) external view returns (uint256 ticket, uint256 license) {
        (ticket, license) = _exits.previewClaimableAmounts(operator);
    }

    /// @inheritdoc IBondingRegistry
    function isLicensed(address operator) external view returns (bool) {
        return operators[operator].licenseBond >= _minLicenseBond();
    }

    /// @inheritdoc IBondingRegistry
    function isRegistered(address operator) external view returns (bool) {
        return operators[operator].registered;
    }

    /// @inheritdoc IBondingRegistry
    function isActive(address operator) external view returns (bool) {
        return operators[operator].active;
    }

    /// @inheritdoc IBondingRegistry
    function hasExitInProgress(address operator) external view returns (bool) {
        Operator memory op = operators[operator];
        return op.exitRequested && block.timestamp < op.exitUnlocksAt;
    }

    // ======================
    // Operator Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function registerOperator() external noExitInProgress(msg.sender) {
        // Clear previous exit request
        if (operators[msg.sender].exitRequested) {
            operators[msg.sender].exitRequested = false;
            operators[msg.sender].exitUnlocksAt = 0;
        }

        require(
            !ISlashingManager(slashingManager).isBanned(msg.sender),
            CiphernodeBanned()
        );
        require(!operators[msg.sender].registered, AlreadyRegistered());
        require(
            operators[msg.sender].licenseBond >= licenseRequiredBond,
            NotLicensed()
        );

        operators[msg.sender].registered = true;

        // CiphernodeRegistry already emits an event when a ciphernode is added
        registry.addCiphernode(msg.sender);

        _updateOperatorStatus(msg.sender);
    }

    /// @inheritdoc IBondingRegistry
    function deregisterOperator() external noExitInProgress(msg.sender) {
        Operator storage op = operators[msg.sender];
        require(op.registered, NotRegistered());

        // block deregistration while an unresolved Lane B slash proposal exists.
        // An operator could otherwise drain ticket / license collateral during the appeal
        // window and leave the slasher with nothing to slash.
        address sm = slashingManager;
        if (sm != address(0)) {
            require(
                !ISlashingManager(sm).hasOpenLaneBProposal(msg.sender),
                OperatorUnderSlash()
            );
        }

        op.registered = false;
        op.exitRequested = true;
        op.exitUnlocksAt = uint64(block.timestamp) + exitDelay;

        uint256 ticketOut = ticketToken.balanceOf(msg.sender);
        uint256 licenseOut = op.licenseBond;
        if (ticketOut != 0) {
            ticketToken.burnTickets(msg.sender, ticketOut);
            emit TicketBalanceUpdated(
                msg.sender,
                -int256(ticketOut),
                0,
                REASON_WITHDRAW
            );
        }
        if (licenseOut != 0) {
            op.licenseBond = 0;
            emit LicenseBondUpdated(
                msg.sender,
                -int256(licenseOut),
                0,
                REASON_UNBOND
            );
        }

        if (ticketOut != 0 || licenseOut != 0) {
            _exits.queueAssetsForExit(
                msg.sender,
                exitDelay,
                ticketOut,
                licenseOut
            );
        }

        // CiphernodeRegistry already emits an event when a ciphernode is removed
        registry.removeCiphernode(msg.sender);

        emit CiphernodeDeregistrationRequested(msg.sender, op.exitUnlocksAt);
        _updateOperatorStatus(msg.sender);
    }

    /// @inheritdoc IBondingRegistry
    function addTicketBalance(
        uint256 amount
    ) external noExitInProgress(msg.sender) {
        require(amount != 0, ZeroAmount());
        require(operators[msg.sender].registered, NotRegistered());

        ticketToken.depositFrom(msg.sender, msg.sender, amount);

        emit TicketBalanceUpdated(
            msg.sender,
            int256(amount),
            ticketToken.balanceOf(msg.sender),
            REASON_DEPOSIT
        );

        _updateOperatorStatus(msg.sender);
    }

    /// @inheritdoc IBondingRegistry
    function removeTicketBalance(
        uint256 amount
    ) external noExitInProgress(msg.sender) {
        require(amount != 0, ZeroAmount());
        require(operators[msg.sender].registered, NotRegistered());
        require(
            ticketToken.balanceOf(msg.sender) >= amount,
            InsufficientBalance()
        );

        ticketToken.burnTickets(msg.sender, amount);
        _exits.queueTicketsForExit(msg.sender, exitDelay, amount);

        emit TicketBalanceUpdated(
            msg.sender,
            -int256(amount),
            ticketToken.balanceOf(msg.sender),
            REASON_WITHDRAW
        );

        _updateOperatorStatus(msg.sender);
    }

    /// @inheritdoc IBondingRegistry
    function bondLicense(
        uint256 amount
    ) external nonReentrant noExitInProgress(msg.sender) {
        _bondLicense(msg.sender, amount);
    }

    /// @inheritdoc IBondingRegistry
    function unbondLicense(
        uint256 amount
    ) external nonReentrant noExitInProgress(msg.sender) {
        require(amount != 0, ZeroAmount());
        require(
            operators[msg.sender].licenseBond >= amount,
            InsufficientBalance()
        );

        operators[msg.sender].licenseBond -= amount;
        _exits.queueLicensesForExit(msg.sender, exitDelay, amount);

        emit LicenseBondUpdated(
            msg.sender,
            -int256(amount),
            operators[msg.sender].licenseBond,
            REASON_UNBOND
        );

        _updateOperatorStatus(msg.sender);
    }

    // ======================
    // Claim Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function claimExits(
        uint256 maxTicketAmount,
        uint256 maxLicenseAmount
    ) external nonReentrant {
        (uint256 ticketClaim, uint256 licenseClaim) = _exits.claimAssets(
            msg.sender,
            maxTicketAmount,
            maxLicenseAmount
        );
        require(ticketClaim > 0 || licenseClaim > 0, ExitNotReady());

        if (ticketClaim > 0) ticketToken.payout(msg.sender, ticketClaim);
        if (licenseClaim > 0) {
            _safeTransferLicenseWithDeltaCheck(msg.sender, licenseClaim);
        }
    }

    // ======================
    // Slashing Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function slashTicketBalance(
        address operator,
        uint256 requestedSlashAmount,
        bytes32 slashReason
    ) external onlySlashingManager returns (uint256) {
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
            _exits.slashPendingAssets(
                operator,
                remainingToSlash,
                0, // licenseAmount
                true
            );
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
    function slashLicenseBond(
        address operator,
        uint256 requestedSlashAmount,
        bytes32 slashReason
    ) external onlySlashingManager nonReentrant {
        require(requestedSlashAmount != 0, ZeroAmount());

        Operator storage operatorData = operators[operator];
        (, uint256 pendingLicenseBalance) = _exits.getPendingAmounts(operator);
        uint256 totalAvailableBalance = operatorData.licenseBond +
            pendingLicenseBalance;
        uint256 actualSlashAmount = Math.min(
            requestedSlashAmount,
            totalAvailableBalance
        );

        if (actualSlashAmount == 0) return;

        uint256 activeSlashAmount = Math.min(
            actualSlashAmount,
            operatorData.licenseBond
        );
        if (activeSlashAmount != 0) {
            operatorData.licenseBond -= activeSlashAmount;
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

        slashedLicenseBond += actualSlashAmount;
        emit LicenseBondUpdated(
            operator,
            -int256(actualSlashAmount),
            operatorData.licenseBond,
            slashReason
        );

        _updateOperatorStatus(operator);
    }

    /// @inheritdoc IBondingRegistry
    function redirectSlashedTicketFunds(
        address to,
        uint256 amount
    ) external onlySlashingManager {
        require(to != address(0), ZeroAddress());
        require(amount > 0, ZeroAmount());
        require(amount <= slashedTicketBalance, InsufficientBalance());

        slashedTicketBalance -= amount;
        ticketToken.payout(to, amount);
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
        require(recipients.length == amounts.length, ArrayLengthMismatch());

        uint256 len = recipients.length;
        for (uint256 i = 0; i < len; i++) {
            if (amounts[i] > 0) {
                rewardToken.safeTransferFrom(
                    msg.sender,
                    recipients[i],
                    amounts[i]
                );
            }
        }
    }

    // ======================
    // Admin Functions
    // ======================

    /// @inheritdoc IBondingRegistry
    function setTicketPrice(uint256 newTicketPrice) public onlyOwner {
        require(newTicketPrice != 0, InvalidConfiguration());

        uint256 oldValue = ticketPrice;
        ticketPrice = newTicketPrice;

        emit ConfigurationUpdated("ticketPrice", oldValue, newTicketPrice);
    }

    /// @inheritdoc IBondingRegistry
    function setLicenseRequiredBond(
        uint256 newLicenseRequiredBond
    ) public onlyOwner {
        require(newLicenseRequiredBond != 0, InvalidConfiguration());

        uint256 oldValue = licenseRequiredBond;
        licenseRequiredBond = newLicenseRequiredBond;

        emit ConfigurationUpdated(
            "licenseRequiredBond",
            oldValue,
            newLicenseRequiredBond
        );
    }

    /// @inheritdoc IBondingRegistry
    function setLicenseActiveBps(uint256 newBps) public onlyOwner {
        require(newBps > 0 && newBps <= BPS_BASE, InvalidConfiguration());

        uint256 oldValue = licenseActiveBps;
        licenseActiveBps = newBps;

        emit ConfigurationUpdated("licenseActiveBps", oldValue, newBps);
    }

    /// @inheritdoc IBondingRegistry
    function setMinTicketBalance(uint256 newMinTicketBalance) public onlyOwner {
        uint256 oldValue = minTicketBalance;
        minTicketBalance = newMinTicketBalance;

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
        require(
            newExitDelay >= MIN_EXIT_DELAY && newExitDelay <= MAX_EXIT_DELAY,
            ExitDelayOutOfBounds(newExitDelay)
        );
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
    function setTicketToken(
        InterfoldTicketToken newTicketToken
    ) public onlyOwner {
        ticketToken = newTicketToken;
        emit TicketTokenSet(address(newTicketToken));
    }

    /// @inheritdoc IBondingRegistry
    function setLicenseToken(IERC20 newLicenseToken) public onlyOwner {
        licenseToken = newLicenseToken;
        emit LicenseTokenSet(address(newLicenseToken));
    }

    /// @inheritdoc IBondingRegistry
    function setRegistry(ICiphernodeRegistry newRegistry) public onlyOwner {
        registry = newRegistry;
        emit RegistrySet(address(newRegistry));
    }

    /// @inheritdoc IBondingRegistry
    function setSlashingManager(address newSlashingManager) public onlyOwner {
        // zero-address protection and explicit event so a missed setter
        // call is observable off-chain.
        require(newSlashingManager != address(0), ZeroAddress());
        address oldValue = slashingManager;
        slashingManager = newSlashingManager;
        emit SlashingManagerUpdated(oldValue, newSlashingManager);
    }

    /// @notice Disabled. Reverts unconditionally.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }

    /// @notice Authorizes an address to distribute rewards
    /// @dev Only callable by owner. Supports multiple authorized distributors (Interfold + E3RefundManager)
    /// @param newRewardDistributor Address to authorize as reward distributor
    function setRewardDistributor(
        address newRewardDistributor
    ) public onlyOwner {
        require(newRewardDistributor != address(0), ZeroAddress());
        // hard cap on the number of authorized reward distributors so
        // payout fan-out loops in downstream consumers stay bounded.
        if (!authorizedDistributors[newRewardDistributor]) {
            require(
                authorizedDistributorCount < MAX_AUTHORIZED_DISTRIBUTORS,
                MaxAuthorizedDistributors()
            );
            authorizedDistributorCount++;
        }
        authorizedDistributors[newRewardDistributor] = true;
        emit RewardDistributorUpdated(newRewardDistributor, true);
    }

    /// @notice Revokes reward distributor authorization
    /// @dev Only callable by owner
    /// @param distributor Address to revoke
    function revokeRewardDistributor(address distributor) public onlyOwner {
        if (authorizedDistributors[distributor]) {
            authorizedDistributorCount--;
        }
        authorizedDistributors[distributor] = false;
        emit RewardDistributorUpdated(distributor, false);
    }

    /// @inheritdoc IBondingRegistry
    function withdrawSlashedFunds(
        uint256 ticketAmount,
        uint256 licenseAmount
    ) public onlyOwner {
        require(ticketAmount <= slashedTicketBalance, InsufficientBalance());
        require(licenseAmount <= slashedLicenseBond, InsufficientBalance());

        if (ticketAmount > 0) {
            slashedTicketBalance -= ticketAmount;
            ticketToken.payout(slashedFundsTreasury, ticketAmount);
        }

        if (licenseAmount > 0) {
            slashedLicenseBond -= licenseAmount;
            _safeTransferLicenseWithDeltaCheck(
                slashedFundsTreasury,
                licenseAmount
            );
        }

        emit SlashedFundsWithdrawn(
            slashedFundsTreasury,
            ticketAmount,
            licenseAmount
        );
    }

    // ======================
    // Internal Functions
    // ======================

    function _bondLicense(address operator, uint256 amount) internal {
        require(operator != address(0), ZeroAddress());
        require(amount != 0, ZeroAmount());

        operators[operator].licenseBond += amount;

        uint256 balanceBefore = licenseToken.balanceOf(address(this));
        licenseToken.safeTransferFrom(operator, address(this), amount);
        uint256 actualReceived = licenseToken.balanceOf(address(this)) -
            balanceBefore;
        require(actualReceived == amount, InvalidAmount());

        emit LicenseBondUpdated(
            operator,
            int256(amount),
            operators[operator].licenseBond,
            REASON_BOND
        );

        _updateOperatorStatus(operator);
    }

    /// @dev Updates operator's active status based on current conditions
    /// @dev Operator is active if: registered, has minimum license bond, and has minimum tickets
    /// @param operator Address of the operator to update
    function _updateOperatorStatus(address operator) internal {
        Operator storage op = operators[operator];
        bool newActiveStatus = op.registered &&
            op.licenseBond >= _minLicenseBond() &&
            (ticketToken.balanceOf(operator) / ticketPrice >= minTicketBalance);

        if (op.active != newActiveStatus) {
            op.active = newActiveStatus;
            if (newActiveStatus) {
                numActiveOperators++;
            } else {
                numActiveOperators--;
            }

            emit OperatorActivationChanged(operator, newActiveStatus);
        }
    }

    /// @dev Calculates the minimum license bond required to maintain active status
    /// @return Minimum license bond (licenseRequiredBond * licenseActiveBps / 10000)
    function _minLicenseBond() internal view returns (uint256) {
        return (licenseRequiredBond * licenseActiveBps) / BPS_BASE;
    }

    /// @dev `safeTransfer` of the license token, measuring the RECIPIENT-side delta
    ///      to detect fee-on-transfer / rebasing behavior (sender-side delta misses
    ///      fees that burn or reroute). Internal accounting is already decremented at
    ///      the call site, so a shortfall emits {LicenseTransferShortfall} rather than
    ///      reverting (a revert would brick claims if the token starts taking fees);
    ///      the owner can swap the token via {setLicenseToken}.
    function _safeTransferLicenseWithDeltaCheck(
        address recipient,
        uint256 expectedAmount
    ) internal {
        uint256 balanceBefore = licenseToken.balanceOf(recipient);
        licenseToken.safeTransfer(recipient, expectedAmount);
        uint256 balanceAfter = licenseToken.balanceOf(recipient);
        uint256 actualReceived = balanceAfter - balanceBefore;
        if (actualReceived != expectedAmount) {
            emit LicenseTransferShortfall(
                recipient,
                expectedAmount,
                actualReceived
            );
        }
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              ERC-165 Interface Detection               //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice ERC-165 interface detection. Advertises
    ///         {IBondingRegistry} and {IERC165}.
    function supportsInterface(
        bytes4 interfaceId
    ) external pure virtual returns (bool) {
        return
            interfaceId == type(IBondingRegistry).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }

    /// @dev Reserved storage slots for future upgrades.
    // solhint-disable-next-line var-name-mixedcase
    uint256[50] private __gap;
}
