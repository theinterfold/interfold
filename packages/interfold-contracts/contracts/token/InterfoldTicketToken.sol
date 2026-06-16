// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    ERC20Wrapper
} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol";
import {
    ERC20Permit
} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {
    ERC20Votes
} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title InterfoldTicketToken (tFOLD)
 * @notice Non-transferable, non-delegatable ERC20Votes wrapper over a stablecoin for operator
 *         staking in the Interfold protocol.
 * @dev SECURITY NOTES
 *
 *      Underlying-blacklist risk: if the wrapped stablecoin (e.g. USDC, USDT) blacklists this
 *      contract, the wrapper cannot move underlying tokens. Withdraw, payout and slashing exits
 *      that move the underlying will revert until the blacklist is cleared. {rescueERC20}
 *      lets the owner sweep accidentally received non-underlying tokens but cannot rescue the
 *      underlying itself.
 *
 *      Registry pointer: at deployment the {registry} can be set instantly via {setRegistry}
 *      so the contract can be wired up after construction. Once {lockRegistry} is invoked any
 *      future change MUST go through {requestRegistryChange} + {activateRegistryChange} with
 *      a {REGISTRY_CHANGE_DELAY} timelock so the active registry cannot be swapped out
 *      instantly to drain operator stake.
 *
 *      EIP-6372 clock: this token uses {block.timestamp} ("mode=timestamp"). The companion
 *      {CiphernodeRegistryOwnable} records committee request timepoints in the same unit so
 *      {getPastVotes} resolves consistently against historical balances.
 */
contract InterfoldTicketToken is
    ERC20,
    ERC20Permit,
    ERC20Votes,
    Ownable2Step,
    ERC20Wrapper,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    /// @notice Thrown when {renounceOwnership} is called.
    error RenounceOwnershipDisabled();

    // ── Custom errors ──────────────────────────────────────────────────────────

    /// @notice Thrown when a function is called by an address other than the registry
    error NotRegistry();

    /// @notice Thrown when attempting to transfer tokens between non-zero addresses
    error TransferNotAllowed();

    /// @notice Thrown when ERC-2612 {permit} is invoked (approvals are disabled on this token).
    error PermitDisabled();

    /// @notice Thrown when a zero address is provided where a valid address is required
    error ZeroAddress();

    /// @notice Thrown when attempting to delegate voting power to any address other than self.
    error DelegationLocked();

    /// @notice Thrown when {setRegistry} is invoked after the registry has been locked.
    error RegistryAlreadyLocked();

    /// @notice Thrown when {requestRegistryChange} is invoked before the registry is locked.
    error RegistryNotLocked();

    /// @notice Thrown when {lockRegistry} is invoked a second time.
    error RegistryLockAlreadySet();

    /// @notice Thrown when there is no pending registry change to activate or cancel.
    error NoPendingRegistry();

    /// @notice Thrown when {activateRegistryChange} is called before the timelock elapses.
    error RegistryChangeNotReady();

    /// @notice Thrown when {rescueERC20} targets the wrapper's underlying asset.
    error CannotRescueUnderlying();

    /// @notice Mandatory delay between requesting and activating a registry swap once locked.
    uint64 public constant REGISTRY_CHANGE_DELAY = 1 days;

    /// @notice Address of the registry contract authorized to mint, burn, and manage ticket tokens
    /// @dev Only this contract can call restricted functions like depositFor, withdrawTo, burnTickets, and payout
    address public registry;

    /// @notice Pending registry address awaiting activation via {activateRegistryChange}.
    address public pendingRegistry;

    /// @notice Unix timestamp at or after which {pendingRegistry} can be activated.
    uint64 public pendingRegistryActivationTime;

    /// @notice Once true, registry changes MUST go through the two-step delayed flow.
    bool public registryLocked;

    /// @notice Tracks slashed funds available for payout (defense-in-depth)
    /// @dev Incremented by burnTickets, decremented by payout. Prevents payout exceeding slashed amount.
    uint256 public payableBalance;

    // ── Events ─────────────────────────────────────────────────────────────────

    /// @notice Emitted whenever {registry} changes (initial set, instant update, or timelocked swap).
    event RegistryChanged(
        address indexed oldRegistry,
        address indexed newRegistry
    );

    /// @notice Emitted when {lockRegistry} is called.
    event RegistryLocked();

    /// @notice Emitted when a delayed registry change is staged.
    event RegistryChangeRequested(
        address indexed newRegistry,
        uint64 activatesAt
    );

    /// @notice Emitted when a previously requested registry change is discarded.
    event RegistryChangeCancelled(address indexed pendingRegistry);

    /// @notice Emitted when the owner rescues an unrelated ERC20 from this contract.
    event ERC20Rescued(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    /// @notice Emitted when a payout is made
    event Payout(address indexed to, uint256 amount);

    /// @notice Restricts function access to only the registry contract
    /// @dev Reverts with NotRegistry if caller is not the registry address
    modifier onlyRegistry() {
        if (msg.sender != registry) revert NotRegistry();
        _;
    }

    /**
     * @notice Initializes the Interfold Ticket Token with name "Interfold Ticket Token" and symbol "tFOLD"
     * @dev Sets the registry pointer directly so deployment never depends on the deployer also
     *      being {initialOwner_}. The registry can be re-pointed instantly until
     *      {lockRegistry} is called.
     * @param baseToken The underlying ERC20 stablecoin to wrap (e.g., USDC, DAI)
     * @param registry_ Address of the registry contract that will manage deposits and withdrawals
     * @param initialOwner_ Address that will own the contract and can update the registry
     */
    constructor(
        IERC20 baseToken,
        address registry_,
        address initialOwner_
    )
        ERC20("Interfold Ticket Token", "tFOLD")
        ERC20Permit("Interfold Ticket Token")
        ERC20Wrapper(baseToken)
        Ownable(initialOwner_)
    {
        if (registry_ == address(0)) revert ZeroAddress();
        registry = registry_;
        emit RegistryChanged(address(0), registry_);
    }

    // ── Registry administration ────────────────────────────────────────────────

    /**
     * @notice Owner-controlled instant registry update. Only available before {lockRegistry}.
     * @dev Intended for post-deployment wiring (the registry typically holds a circular dependency
     *      to this token). Reverts once the registry is locked to prevent an instant drain vector.
     */
    function setRegistry(address newRegistry) external onlyOwner {
        if (registryLocked) revert RegistryAlreadyLocked();
        if (newRegistry == address(0)) revert ZeroAddress();
        address old = registry;
        registry = newRegistry;
        emit RegistryChanged(old, newRegistry);
    }

    /**
     * @notice One-way switch that forces every future registry swap through the delayed flow.
     */
    function lockRegistry() external onlyOwner {
        if (registryLocked) revert RegistryLockAlreadySet();
        registryLocked = true;
        emit RegistryLocked();
    }

    /**
     * @notice Stage a registry swap that becomes activatable after {REGISTRY_CHANGE_DELAY}.
     */
    function requestRegistryChange(address newRegistry) external onlyOwner {
        if (!registryLocked) revert RegistryNotLocked();
        if (newRegistry == address(0)) revert ZeroAddress();
        pendingRegistry = newRegistry;
        uint64 activatesAt = uint64(block.timestamp) + REGISTRY_CHANGE_DELAY;
        pendingRegistryActivationTime = activatesAt;
        emit RegistryChangeRequested(newRegistry, activatesAt);
    }

    /**
     * @notice Apply a previously requested registry swap once the timelock has elapsed.
     */
    function activateRegistryChange() external onlyOwner {
        address pending = pendingRegistry;
        if (pending == address(0)) revert NoPendingRegistry();
        if (block.timestamp < pendingRegistryActivationTime) {
            revert RegistryChangeNotReady();
        }
        address old = registry;
        registry = pending;
        pendingRegistry = address(0);
        pendingRegistryActivationTime = 0;
        emit RegistryChanged(old, pending);
    }

    /**
     * @notice Discard a pending registry change.
     */
    function cancelRegistryChange() external onlyOwner {
        address pending = pendingRegistry;
        if (pending == address(0)) revert NoPendingRegistry();
        pendingRegistry = address(0);
        pendingRegistryActivationTime = 0;
        emit RegistryChangeCancelled(pending);
    }

    // ── Deposits / withdrawals ────────────────────────────────────────────────

    /**
     * @notice Deposit underlying tokens and mint the actual amount received (fee-on-transfer safe).
     * @dev Only callable by the registry contract. Mints based on the delta in the wrapper's
     *      underlying balance instead of the requested {amount}, defending against
     *      fee-on-transfer or rebasing stablecoins that would otherwise let an operator mint
     *      tickets the wrapper is not actually backed by. Auto-delegates the operator to
     *      themselves so {getPastVotes} reflects their balance immediately.
     * @param operator Address to receive the minted ticket tokens
     * @param amount Nominal amount of underlying tokens to pull from the caller
     * @return success Always true on success
     */
    function depositFor(
        address operator,
        uint256 amount
    ) public override onlyRegistry nonReentrant returns (bool success) {
        if (operator == address(0) || operator == address(this)) {
            revert ZeroAddress();
        }
        IERC20 underlying_ = IERC20(address(underlying()));
        uint256 balanceBefore = underlying_.balanceOf(address(this));
        underlying_.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = underlying_.balanceOf(address(this)) - balanceBefore;
        _mint(operator, received);
        if (delegates(operator) == address(0)) _delegate(operator, operator);
        return true;
    }

    /**
     * @notice Deposit underlying from `from` and mint actual received amount to `to`.
     * @dev Only callable by the registry contract. Same fee-on-transfer protection as
     *      {depositFor}.
     */
    function depositFrom(
        address from,
        address to,
        uint256 amount
    ) external onlyRegistry nonReentrant returns (bool) {
        if (to == address(0) || to == address(this)) revert ZeroAddress();
        IERC20 underlying_ = IERC20(address(underlying()));
        uint256 balanceBefore = underlying_.balanceOf(address(this));
        underlying_.safeTransferFrom(from, address(this), amount);
        uint256 received = underlying_.balanceOf(address(this)) - balanceBefore;
        _mint(to, received);
        if (delegates(to) == address(0)) _delegate(to, to);
        return true;
    }

    /**
     * @notice Burns ticket tokens from the registry and transfers underlying tokens to a receiver
     * @dev Only callable by the registry contract. Burns ticket tokens from the registry's balance
     *      and transfers an equivalent amount of underlying tokens to the receiver address. Used
     *      when operators unstake their tokens.
     * @param receiver Address to receive the underlying tokens
     * @param amount Number of ticket tokens to burn and underlying tokens to transfer
     * @return success True if the burn and transfer succeeded
     */
    function withdrawTo(
        address receiver,
        uint256 amount
    ) public override onlyRegistry nonReentrant returns (bool success) {
        return super.withdrawTo(receiver, amount);
    }

    /**
     * @notice Burns ticket tokens from an operator's balance without transferring underlying tokens
     * @dev Only callable by the registry contract. Used for slashing or penalizing operators where
     *      the underlying tokens should remain in the contract or be handled separately. Does not
     *      return underlying tokens to the operator.
     * @param operator Address whose ticket tokens will be burned
     * @param amount Number of ticket tokens to burn from the operator's balance
     */
    function burnTickets(
        address operator,
        uint256 amount
    ) external onlyRegistry {
        payableBalance += amount;
        _burn(operator, amount);
    }

    /**
     * @notice Transfer underlying tokens to an address without burning ticket tokens.
     * @dev Only callable by the registry contract.
     * @param to Address to payout to.
     * @param amount Amount of ticket tokens to payout.
     */
    function payout(address to, uint256 amount) external onlyRegistry {
        require(amount <= payableBalance, "Exceeds payable balance");
        payableBalance -= amount;
        SafeERC20.safeTransfer(IERC20(address(underlying())), to, amount);
        emit Payout(to, amount);
    }

    /**
     * @notice Owner-only escape hatch for tokens accidentally sent to this contract.
     * @dev Refuses to touch the wrapped underlying so it cannot be used to rug operators.
     * @param token  ERC20 to rescue (must not equal {underlying}).
     * @param to     Recipient of the rescued tokens.
     * @param amount Amount to send.
     */
    function rescueERC20(
        IERC20 token,
        address to,
        uint256 amount
    ) external onlyOwner {
        if (address(token) == address(underlying())) {
            revert CannotRescueUnderlying();
        }
        if (to == address(0)) revert ZeroAddress();
        token.safeTransfer(to, amount);
        emit ERC20Rescued(address(token), to, amount);
    }

    // ── Disabled flows ─────────────────────────────────────────────────────────

    /**
     * @dev Override approve to revert — ticket tokens are non-transferable.
     */
    function approve(address, uint256) public pure override returns (bool) {
        revert TransferNotAllowed();
    }

    /**
     * @dev ERC-2612 permit is disabled because allowances are disabled.
     */
    function permit(
        address,
        address,
        uint256,
        uint256,
        uint8,
        bytes32,
        bytes32
    ) public pure override {
        revert PermitDisabled();
    }

    /**
     * @notice Override ERC20Votes update hook to prevent transfers between users.
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Votes) {
        if (from != address(0) && to != address(0)) {
            revert TransferNotAllowed();
        }
        super._update(from, to, value);
    }

    /**
     * @notice Only self-delegation is allowed (and only as a no-op).
     * @dev Voting power is auto-self-delegated on deposit so the only valid call is a redundant
     *      self-delegate. Anything else reverts with {DelegationLocked}.
     */
    function delegate(address delegatee) public override {
        if (delegatee != msg.sender) revert DelegationLocked();
        if (delegates(msg.sender) != msg.sender) {
            _delegate(msg.sender, msg.sender);
        }
    }

    /**
     * @notice Delegation-by-signature is not supported; voting power is auto-self-delegated.
     */
    function delegateBySig(
        address,
        uint256,
        uint256,
        uint8,
        bytes32,
        bytes32
    ) public pure override {
        revert DelegationLocked();
    }

    /**
     * @dev Expose decimals from the underlying token.
     */
    function decimals()
        public
        view
        override(ERC20, ERC20Wrapper)
        returns (uint8)
    {
        return super.decimals();
    }

    /**
     * @dev Expose permit nonces via both ERC20Permit and OpenZeppelin Nonces.
     */
    function nonces(
        address owner
    ) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    // ── EIP-6372 clock (timestamp mode) ───────────────────────────────────────

    /// @notice EIP-6372 clock — uses {block.timestamp} so timepoints align with the registry.
    function clock() public view override returns (uint48) {
        return uint48(block.timestamp);
    }

    /// @notice EIP-6372 clock mode.
    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() public pure override returns (string memory) {
        return "mode=timestamp";
    }

    /// @notice Disabled. Reverts unconditionally.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }
}
