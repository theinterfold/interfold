// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {
    ERC20Permit,
    Nonces
} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {
    ERC20Votes
} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {
    AccessControl
} from "@openzeppelin/contracts/access/AccessControl.sol";

import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";

/**
 * @title InterfoldToken
 * @notice The governance and utility token for the Interfold protocol, with
 *         wallet-level lock enforcement designed around the Uniswap CCA
 *         distribution flow.
 *
 */
contract InterfoldToken is
    ERC20,
    ERC20Permit,
    ERC20Votes,
    Ownable2Step,
    AccessControl
{
    // ─────────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Global token lifecycle phase, derived from the immutable CCA
    ///         window and the TGE: Virtual (pre-sale), CCA (CCA
    ///         bidding window), Cooldown (sale ended, TGE not yet fired),
    ///         Live (TGE fired).
    enum Phase {
        Virtual,
        CCA,
        Cooldown,
        Live
    }

    enum Anchor {
        Absolute,
        Tge
    }

    /// @param anchor How the curve's start resolves (Absolute or Tge).
    /// @param start Anchor timestamp when {anchor} is Absolute; must be zero
    ///        when {anchor} is Tge.
    /// @param cliffDuration Seconds after the anchor before anything releases.
    /// @param vestDuration Total linear release duration measured from the
    ///        anchor; zero means everything releases at the cliff.
    struct Curve {
        Anchor anchor;
        uint64 start;
        uint64 cliffDuration;
        uint64 vestDuration;
    }

    /// @notice Token-level lock policy with a single unlock curve.
    /// @dev This token enforces token unlock schedules only. Service vesting
    ///      schedules that continue after TGE may live in a separate vesting
    ///      contract.
    /// @param holdUntil Optional absolute timestamp before which nothing is
    ///        transferable, whatever the unlock curve has accrued;
    /// @param unlock Unlock curve.
    struct LockPolicy {
        uint64 holdUntil;
        Curve unlock;
    }

    struct Lock {
        bytes32 policyId;
        uint256 amount;
    }

    struct MintAllocation {
        address recipient;
        uint256 amount;
        bytes32 policyId;
        bytes32 label;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice A zero address was provided where a valid address is required.
    error ZeroAddress();

    /// @notice A zero amount or zero timestamp was provided where a non-zero
    ///         value is required.
    error ZeroAmount();

    /// @notice Minting would exceed {MAX_SUPPLY}.
    error MaxSupplyExceeded();

    /// @notice The transfer is not one of the movements allowed pre-TGE:
    ///         bonding (the registry on either side) or a CCA distribution
    ///         ({CLAIM_SOURCE} sending, any phase).
    error TransferRestricted(address from, address to);

    /// @notice {mint} or {mintAllocations} was called after the Virtual phase; the
    ///         full supply is distributed before {CCA_START}.
    error MintingClosed();

    /// @notice {tge} was called but the token is already live.
    error AlreadyLive();

    /// @notice {tge} was called before {CCA_END} + {TGE_COOLDOWN}.
    error TgeTooEarly(uint64 current, uint64 notBefore);

    /// @notice The CCA window is empty, inverted, or does not start in the
    ///         future.
    error InvalidCcaWindow(uint64 ccaStart, uint64 ccaEnd);

    /// @notice Policy parameters are internally inconsistent, or the policy
    ///         could keep tokens locked past the lock sunset.
    error InvalidPolicy();

    /// @notice The lock sunset timestamp must be after the earliest TGE.
    error InvalidNoMoreLocks(uint256 noMoreLocks, uint256 minimum);

    /// @notice The requested relink amount exceeds the amount available under
    ///         the source policy.
    error RelinkAmountExceeded();

    /// @notice An account has reached the maximum number of active lock
    ///         policy entries.
    error TooManyLocks();

    /// @notice An account has reached the maximum number of queued lock
    ///         policy entries.
    error TooManyQueuedLocks();

    /// @notice The policy id is already defined; policies are write-once.
    error PolicyAlreadyDefined(bytes32 policyId);

    /// @notice The referenced policy id has not been defined.
    error PolicyNotDefined(bytes32 policyId);

    /// @notice A transfer of `value` exceeds the sender's spendable balance
    ///         (balance + bonded − locked balance).
    error InsufficientUnlockedBalance(
        address account,
        uint256 spendable,
        uint256 value
    );

    /// @notice The bonding registry address has no deployed code.
    error InvalidBondingRegistry(address registry);

    /// @notice Thrown when {renounceOwnership} is called. Ownership is
    ///         critical for protocol governance; renouncing would permanently
    ///         freeze admin functions and is disallowed.
    error RenounceOwnershipDisabled();

    // ─────────────────────────────────────────────────────────────────────────
    // Constants and immutables
    // ─────────────────────────────────────────────────────────────────────────

    uint256 public constant MAX_SUPPLY = 1_200_000_000e18;

    /// @notice Role authorized to mint allocations, while Virtual.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @notice Role authorized to manage the pre-TGE transfer whitelist.
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    /// @notice Role authorized to create lock policies and manage claim-lock
    ///         exemptions.
    bytes32 public constant LOCK_MANAGER_ROLE = keccak256("LOCK_MANAGER_ROLE");

    /// @notice Minimum time between {CCA_END} and {tge}.
    uint64 public constant TGE_COOLDOWN = 45 days;

    bytes32 public constant PENDING_LOCK_POLICY_ID = "PENDING";

    /// @notice Maximum number of distinct active lock policies an account may
    ///         hold. Protects against unbounded gas costs in {_update}.
    uint256 public constant MAX_LOCKS_PER_ACCOUNT = 8;

    /// @notice Maximum number of distinct queued lock policies an account may
    ///         hold.
    uint256 public constant MAX_QUEUED_LOCKS_PER_ACCOUNT = 8;

    /// @notice Start of the CCA auction window, fixed at deployment.
    uint64 public immutable CCA_START;

    /// @notice End of the CCA auction window, fixed at deployment
    uint64 public immutable CCA_END;

    /// @notice Absolute timestamp after which token locks no longer apply.
    uint64 public immutable NO_MORE_LOCKS;

    /// @notice The CCA auction contract
    address public immutable CLAIM_SOURCE;

    /// @notice Registry whose bonded INTF counts toward locked balances.
    IBondingRegistry public immutable BONDING_REGISTRY;

    // ─────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice TGE timestamp; zero until {tge} is called, then immutable.
    uint64 public tgeTimestamp;

    /// @notice Addresses allowed to transfer before TGE.
    mapping(address account => bool whitelisted) public transferWhitelist;

    /// @notice Addresses exempt from automatic claim-source lock creation.
    mapping(address account => bool exempt) public claimLockExempt;

    /// @notice Write-once lock policies by id.
    mapping(bytes32 policyId => LockPolicy policy) internal lockPolicies;

    /// @notice Active locks by account.
    mapping(address account => Lock[] entries) public locks;

    /// @notice Policy buckets for links that arrived before enough claim
    ///         balance existed to classify them.
    mapping(address account => Lock[] entries) public queuedLocks;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Emitted for every mint instruction.
    event AllocationMinted(
        address indexed recipient,
        uint256 amount,
        bytes32 indexed policyId,
        bytes32 indexed label
    );

    /// @notice Emitted when a lock policy is defined (write-once).
    event PolicyDefined(bytes32 indexed policyId, LockPolicy policy);

    /// @notice Emitted when an account's transfer whitelist status changes.
    event TransferWhitelistUpdated(address indexed account, bool whitelisted);

    /// @notice Emitted when an account's claim-lock exemption status changes.
    event ClaimLockExemptUpdated(address indexed account, bool exempt);

    /// @notice Emitted whenever an active lock amount changes; `amount` is
    ///         the new total under `policyId`.
    event ActiveLockUpdated(
        address indexed account,
        bytes32 indexed policyId,
        uint256 amount
    );

    /// @notice Emitted whenever a queued lock amount changes; `amount` is
    ///         the new remaining queued total under `policyId`.
    event QueuedLockUpdated(
        address indexed account,
        bytes32 indexed policyId,
        uint256 amount
    );

    /// @notice Emitted when an active lock is moved from one policy to
    ///         another via {relinkActiveLock}.
    event ActiveLockRelinked(
        address indexed account,
        bytes32 indexed fromPolicyId,
        bytes32 indexed toPolicyId,
        uint256 amount
    );

    /// @notice Emitted once, when {tge} fires.
    event TgeTriggered(uint64 timestamp);

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Deploys INTF with no TGE set.
     * @dev The initial owner receives every role via the {_transferOwnership}
     *      sync. Operational roles can additionally be granted to dedicated
     *      keys post-deployment.
     * @param initialOwner_ Initial owner; receives all roles.
     * @param ccaStart_ CCA auction window start;
     * @param ccaEnd_ CCA auction window end; after `ccaStart_`.
     * @param noMoreLocks_ Absolute timestamp after which token locks no longer apply.
     * @param claimSource_ The CCA auction contract
     * @param bondingRegistry_ Registry whose bonded INTF
     */
    constructor(
        address initialOwner_,
        uint64 ccaStart_,
        uint64 ccaEnd_,
        uint64 noMoreLocks_,
        address claimSource_,
        IBondingRegistry bondingRegistry_
    )
        ERC20("Interfold", "INTF")
        ERC20Permit("Interfold")
        Ownable(initialOwner_)
    {
        if (ccaStart_ <= block.timestamp) {
            revert InvalidCcaWindow(ccaStart_, ccaEnd_);
        }
        if (ccaEnd_ <= ccaStart_) revert InvalidCcaWindow(ccaStart_, ccaEnd_);
        if (claimSource_ == address(0)) revert ZeroAddress();
        address registry = address(bondingRegistry_);
        if (registry == address(0)) revert ZeroAddress();
        if (registry.code.length == 0) {
            revert InvalidBondingRegistry(registry);
        }
        if (noMoreLocks_ == 0) revert ZeroAmount();
        uint256 earliestTge = uint256(ccaEnd_) + TGE_COOLDOWN;
        if (noMoreLocks_ <= earliestTge) {
            revert InvalidNoMoreLocks(noMoreLocks_, earliestTge + 1);
        }
        CCA_START = ccaStart_;
        CCA_END = ccaEnd_;
        NO_MORE_LOCKS = noMoreLocks_;
        CLAIM_SOURCE = claimSource_;
        BONDING_REGISTRY = bondingRegistry_;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Minting
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Plain vanilla admin mint: INTF with no lock attached. Only
    ///         allowed during the Virtual phase.
    function mint(
        address recipient,
        uint256 amount,
        bytes32 label
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (phase() != Phase.Virtual) revert MintingClosed();
        _mintTokens(recipient, amount);
        emit AllocationMinted(recipient, amount, bytes32(0), label);
    }

    /// @notice Mints allocations locked under their policies; the path the
    ///         minter role uses to distribute vested supply. Only allowed
    ///         during the Virtual phase.
    /// @dev Team / GG "vested as of TGE" amounts must be calculated
    ///      off-chain using the expected TGE date, since {tgeTimestamp} is
    ///      not known when Virtual minting closes at {CCA_START}.
    function mintAllocations(
        MintAllocation[] calldata allocations
    ) external onlyRole(MINTER_ROLE) {
        if (phase() != Phase.Virtual) revert MintingClosed();
        uint256 len = allocations.length;
        for (uint256 i = 0; i < len; i++) {
            _mintAllocation(allocations[i]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Launch lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Sets {tgeTimestamp} to the current block timestamp, exactly once.
     * @dev Permissionless: anyone may trigger the TGE once {CCA_END} +
     *      {TGE_COOLDOWN} has passed, so launch cannot be stalled by an idle
     *      operator.
     */
    function tge() external {
        if (tgeTimestamp != 0) revert AlreadyLive();
        uint64 current = uint64(block.timestamp);
        uint64 earliest = CCA_END + TGE_COOLDOWN;
        if (current < earliest) revert TgeTooEarly(current, earliest);
        tgeTimestamp = current;
        emit TgeTriggered(current);
    }

    /// @notice Current lifecycle phase. Live is event-driven ({tge}); the
    ///         earlier phases derive from the immutable CCA window.
    function phase() public view returns (Phase) {
        if (tgeTimestamp != 0) return Phase.Live;

        uint64 current = uint64(block.timestamp);
        if (current < CCA_START) return Phase.Virtual;
        if (current < CCA_END) return Phase.CCA;
        return Phase.Cooldown;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Whitelisting
    // ─────────────────────────────────────────────────────────────────────────

    function setTransferWhitelisted(
        address account,
        bool whitelisted
    ) external onlyRole(WHITELIST_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        transferWhitelist[account] = whitelisted;
        emit TransferWhitelistUpdated(account, whitelisted);
    }

    /// @notice Sets whether `account` is exempt from automatic claim-lock
    ///         creation when receiving tokens from {CLAIM_SOURCE}.
    function setClaimLockExempt(
        address account,
        bool exempt
    ) external onlyRole(LOCK_MANAGER_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        claimLockExempt[account] = exempt;
        emit ClaimLockExemptUpdated(account, exempt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lock configuration
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Creates a lock policy. Policies are write-once: once created,
     *         the terms backing existing locks can never be changed, by anyone.
     * @param policyId Non-zero identifier, e.g. bytes32("CCA_REG_S").
     * @param policy Lock terms. The unlock curve is required, must lock
     *        something, and must be consistent with its anchor mode;
     *        `holdUntil` is optional (zero = none).
     */
    function createLockPolicy(
        bytes32 policyId,
        LockPolicy calldata policy
    ) external onlyRole(LOCK_MANAGER_ROLE) {
        if (policyId == bytes32(0) || policyId == PENDING_LOCK_POLICY_ID) {
            revert InvalidPolicy();
        }

        if (_policyDefined(policyId)) {
            revert PolicyAlreadyDefined(policyId);
        }
        _validateCurve(policy.unlock);
        _validatePolicyMaturity(policy);

        lockPolicies[policyId] = policy;
        emit PolicyDefined(policyId, policy);
    }

    /**
     * @notice Links `amount` of `account`'s claims to `policyId` — the
     *         Predicate/KYC bucket import.
     *
     *         Claims from the CCA can come before or after the operator's
     *         linkClaim. {_claim} and {_linkClaim} manipulate {locks} and
     *         {queuedLocks} to link balances to policies in a resilient
     *         way: it doesn't matter who calls what first.
     *
     *         Each wallet is expected to have at most one CCA policy bucket.
     *         If a wallet has multiple queued CCA policies, claim matching
     *         is not business-order aware and should be treated as
     *         undefined. The importer must not create multiple queued CCA
     *         buckets for the same wallet.
     */
    function linkClaim(
        address account,
        uint256 amount,
        bytes32 policyId
    ) external onlyRole(LOCK_MANAGER_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (!_policyDefined(policyId)) revert PolicyNotDefined(policyId);

        _linkClaim(account, amount, policyId);
    }

    /**
     * @notice Corrects an active lock that was incorrectly linked to the
     *         wrong policy. Only allowed before TGE (Live phase).
     * @dev This is a safety hatch for admin mistakes during lock import;
     *      it is not intended for routine use. The {PENDING_LOCK_POLICY_ID}
     *      policy cannot be used as source or target.
     */
    function relinkActiveLock(
        address account,
        bytes32 fromPolicyId,
        bytes32 toPolicyId,
        uint256 amount
    ) external onlyRole(LOCK_MANAGER_ROLE) {
        if (tgeTimestamp != 0) revert AlreadyLive();
        _validateRelinkParams(account, fromPolicyId, toPolicyId, amount);
        if (_activeLockAmount(account, fromPolicyId) < amount) {
            revert RelinkAmountExceeded();
        }

        (uint256 consumed, ) = _consumeLock(
            account,
            locks[account],
            fromPolicyId,
            amount,
            true
        );

        _addOrIncrementLock(
            account,
            locks[account],
            toPolicyId,
            consumed,
            true
        );

        emit ActiveLockRelinked(account, fromPolicyId, toPolicyId, consumed);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lock views
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Current locked balance of `account`: the amount that must remain
    ///         controlled (wallet balance + bonded) by the account.
    function lockedBalanceOf(address account) public view returns (uint256) {
        return lockedBalanceAt(account, uint64(block.timestamp));
    }

    /// @notice Locked balance of `account` at `timestamp`, evaluated against the
    ///         current configuration (an unset TGE keeps {Anchor.Tge} policies
    ///         fully locked for any timestamp). Always zero from the lock
    ///         sunset onwards.
    function lockedBalanceAt(
        address account,
        uint64 timestamp
    ) public view returns (uint256 lockedBalance) {
        if (timestamp >= NO_MORE_LOCKS) {
            return 0;
        }

        Lock[] storage accountLocks = locks[account];
        for (uint256 i = 0; i < accountLocks.length; i++) {
            Lock storage accountLock = accountLocks[i];
            bytes32 policyId = accountLock.policyId;
            uint256 amount = accountLock.amount;
            if (policyId == PENDING_LOCK_POLICY_ID) {
                // Unclassified claims are fully locked, immune to time.
                lockedBalance += amount;
            } else {
                lockedBalance += _lockedAmount(
                    lockPolicies[policyId],
                    amount,
                    timestamp
                );
            }
        }
    }

    /// @notice Wallet balance `account` can transfer right now: the wallet
    ///         must retain whatever part of its locked balance its bond does
    ///         not already cover.
    /// @dev Never consults the registry for accounts with nothing locked.
    function transferableBalanceOf(
        address account
    ) public view returns (uint256) {
        uint256 balance = balanceOf(account);
        uint256 lockedBalance = lockedBalanceOf(account);
        if (lockedBalance == 0) return balance;

        uint256 bondedBalance = BONDING_REGISTRY.totalBonded(account);
        uint256 mustRetain = lockedBalance > bondedBalance
            ? lockedBalance - bondedBalance
            : 0;
        return balance > mustRetain ? balance - mustRetain : 0;
    }

    /// @notice Returns the full lock policy for `policyId`, or an empty
    ///         struct if the policy has not been defined.
    function lockPolicyOf(
        bytes32 policyId
    ) external view returns (LockPolicy memory) {
        return lockPolicies[policyId];
    }

    /// @notice Number of distinct lock policy entries for `account`.
    function lockCount(address account) external view returns (uint256) {
        return locks[account].length;
    }

    /// @notice Number of distinct queued lock policy entries for `account`.
    function queuedLockCount(address account) external view returns (uint256) {
        return queuedLocks[account].length;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transfer hook
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @dev Applies, in order:
     *      1. The lock sunset short-circuit.
     *      2. The pre-TGE transfer gate (_isTransferRestricted)
     *      3. The lock check, the sender can move at most its transferable
     *         balance
     *      4. The transfer itself, via parent contract
     *      5. Claim-lock creation, unless the recipient is claim-lock exempt.
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Votes) {
        if (block.timestamp >= NO_MORE_LOCKS) {
            super._update(from, to, value);
            return;
        }

        bool isMint = from == address(0);
        bool isBurn = to == address(0);

        if (_isTransferRestricted(from, to)) {
            revert TransferRestricted(from, to);
        }

        if (!isMint) {
            uint256 transferable = transferableBalanceOf(from);
            if (value > transferable) {
                revert InsufficientUnlockedBalance(from, transferable, value);
            }
        }

        super._update(from, to, value);

        // from == CLAIM_SOURCE implies neither mint nor an unset claim source.
        if (
            !isBurn &&
            value != 0 &&
            from == CLAIM_SOURCE &&
            !claimLockExempt[to]
        ) {
            _claim(to, value);
        }
    }

    /// @dev Whether a transfer from `from` to `to` is blocked by the
    ///      pre-TGE gate. Always false once {tge} fires; mints and burns
    ///      are never gated. The locked-balance check
    ///      ({transferableBalanceOf}) applies independently.
    function _isTransferRestricted(
        address from,
        address to
    ) internal view returns (bool) {
        if (tgeTimestamp != 0) return false;
        if (from == address(0) || to == address(0)) return false;

        address registry = address(BONDING_REGISTRY);
        bool isBonding = from == registry || to == registry;
        // The claim source is trusted in any phase: the CCA enforces its own
        // (block-based) claim timing. Every distribution still lands in a
        // lock via {_claim}.
        bool isCcaDistribution = from == CLAIM_SOURCE;
        bool isWhitelisted = transferWhitelist[from] || transferWhitelist[to];
        return !isBonding && !isCcaDistribution && !isWhitelisted;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internals
    // ─────────────────────────────────────────────────────────────────────────

    function _mintAllocation(MintAllocation calldata allocation) internal {
        // Every batch allocation is locked under a policy; unlocked supply
        // goes through {mint}.
        if (allocation.policyId == bytes32(0)) {
            revert InvalidPolicy();
        }

        if (!_policyDefined(allocation.policyId)) {
            revert PolicyNotDefined(allocation.policyId);
        }

        _mintTokens(allocation.recipient, allocation.amount);
        _addOrIncrementLock(
            allocation.recipient,
            locks[allocation.recipient],
            allocation.policyId,
            allocation.amount,
            true
        );
        emit AllocationMinted(
            allocation.recipient,
            allocation.amount,
            allocation.policyId,
            allocation.label
        );
    }

    /// @dev Shared mint path: amount and supply-cap validation plus the
    ///      ERC20 mint itself.
    function _mintTokens(address recipient, uint256 amount) internal {
        if (amount == 0) revert ZeroAmount();
        if (totalSupply() + amount > MAX_SUPPLY) {
            revert MaxSupplyExceeded();
        }
        _mint(recipient, amount);
    }

    /// @dev Claim behavior:
    ///
    ///      - When a claim arrives, greedily fill queued policy buckets until
    ///        the claim amount is exhausted.
    ///      - Each consumed portion is moved into active locks under the
    ///        bucket's policyId. A claim may fully consume a bucket or
    ///        partially consume the current bucket.
    ///      - Any claim amount left after all queued buckets are consumed
    ///        lands as { PENDING_LOCK_POLICY_ID }.
    ///
    ///      Note: no order guarantees on claims and links.
    function _claim(address account, uint256 amount) private {
        uint256 remaining = amount;
        while (remaining != 0) {
            (uint256 consumed, bytes32 policyId) = _consumeLock(
                account,
                queuedLocks[account],
                bytes32(0),
                remaining,
                false
            );

            if (consumed == 0) {
                policyId = PENDING_LOCK_POLICY_ID;
                consumed = remaining;
            }

            _addOrIncrementLock(
                account,
                locks[account],
                policyId,
                consumed,
                true
            );
            remaining -= consumed;
        }
    }

    /// @dev Link behavior:
    ///
    ///      - When linking a claim amount to a real policyId, consume as much
    ///        active pending balance as possible.
    ///      - The consumed portion moves from {PENDING_LOCK_POLICY_ID} into
    ///        an active lock under {policyId}.
    ///      - Any unfilled remainder increments that policy's queued bucket
    ///        for future claims to consume.
    ///
    ///      Note: no order guarantees on claims and links.
    function _linkClaim(
        address account,
        uint256 amount,
        bytes32 policyId
    ) private {
        (uint256 consumed, ) = _consumeLock(
            account,
            locks[account],
            PENDING_LOCK_POLICY_ID,
            amount,
            true
        );
        uint256 remaining = amount - consumed;

        // if we consumed from PENDING policy, add the real thing
        if (consumed != 0) {
            _addOrIncrementLock(
                account,
                locks[account],
                policyId,
                consumed,
                true
            );
        }

        // Whatever is left queues under the target policy.
        if (remaining != 0) {
            _addOrIncrementLock(
                account,
                queuedLocks[account],
                policyId,
                remaining,
                false
            );
        }
    }

    /// @dev Finds the index of `filterPolicyId` in `entries`. Returns
    ///      (0, false) when not found, or when `filterPolicyId` is zero
    ///      and `entries` is empty.
    function _findLockIndex(
        Lock[] storage entries,
        bytes32 filterPolicyId
    ) internal view returns (uint256 index, bool found) {
        uint256 len = entries.length;
        if (filterPolicyId != bytes32(0)) {
            for (uint256 i = 0; i < len; i++) {
                if (entries[i].policyId == filterPolicyId) {
                    return (i, true);
                }
            }
            return (0, false);
        }
        return (0, len > 0);
    }

    function _consumeLock(
        address account,
        Lock[] storage entries,
        bytes32 filterPolicyId,
        uint256 amount,
        bool isActive
    ) internal returns (uint256 consumed, bytes32 consumedPolicyId) {
        (uint256 i, bool found) = _findLockIndex(entries, filterPolicyId);
        if (!found) return (0, bytes32(0));

        consumedPolicyId = entries[i].policyId;
        consumed = entries[i].amount;
        assert(consumed > 0);
        if (consumed > amount) {
            consumed = amount;
        }

        uint256 remaining = entries[i].amount - consumed;
        if (remaining == 0) {
            _removeLockAt(entries, i);
        } else {
            entries[i].amount = remaining;
        }

        if (isActive) {
            emit ActiveLockUpdated(account, consumedPolicyId, remaining);
        } else {
            emit QueuedLockUpdated(account, consumedPolicyId, remaining);
        }
    }

    function _addOrIncrementLock(
        address account,
        Lock[] storage entries,
        bytes32 policyId,
        uint256 amount,
        bool isActive
    ) internal returns (uint256 newAmount) {
        uint256 len = entries.length;
        for (uint256 i = 0; i < len; i++) {
            if (entries[i].policyId == policyId) {
                entries[i].amount += amount;
                newAmount = entries[i].amount;
                if (isActive) {
                    emit ActiveLockUpdated(account, policyId, newAmount);
                } else {
                    emit QueuedLockUpdated(account, policyId, newAmount);
                }
                return newAmount;
            }
        }
        if (isActive && len >= MAX_LOCKS_PER_ACCOUNT) revert TooManyLocks();
        if (!isActive && len >= MAX_QUEUED_LOCKS_PER_ACCOUNT) {
            revert TooManyQueuedLocks();
        }
        entries.push(Lock(policyId, amount));
        if (isActive) {
            emit ActiveLockUpdated(account, policyId, amount);
        } else {
            emit QueuedLockUpdated(account, policyId, amount);
        }
        return amount;
    }

    function _removeLockAt(Lock[] storage entries, uint256 index) internal {
        entries[index] = entries[entries.length - 1];
        entries.pop();
    }

    function _policyDefined(bytes32 policyId) internal view returns (bool) {
        Curve storage unlock = lockPolicies[policyId].unlock;
        return unlock.cliffDuration != 0 || unlock.vestDuration != 0;
    }

    /// @dev Validates {relinkActiveLock} parameters. Extracted to keep the
    ///      external function below the solhint cyclomatic-complexity cap.
    function _validateRelinkParams(
        address account,
        bytes32 fromPolicyId,
        bytes32 toPolicyId,
        uint256 amount
    ) internal view {
        if (account == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (fromPolicyId == bytes32(0) || toPolicyId == bytes32(0)) {
            revert InvalidPolicy();
        }
        if (fromPolicyId == toPolicyId) revert InvalidPolicy();
        if (
            fromPolicyId == PENDING_LOCK_POLICY_ID ||
            toPolicyId == PENDING_LOCK_POLICY_ID
        ) revert InvalidPolicy();
        if (!_policyDefined(fromPolicyId)) {
            revert PolicyNotDefined(fromPolicyId);
        }
        if (!_policyDefined(toPolicyId)) {
            revert PolicyNotDefined(toPolicyId);
        }
    }

    /// @dev Returns the active lock amount for `account` under `policyId`,
    ///      or zero if no such lock exists.
    function _activeLockAmount(
        address account,
        bytes32 policyId
    ) internal view returns (uint256) {
        Lock[] storage accountLocks = locks[account];
        for (uint256 i = 0; i < accountLocks.length; i++) {
            if (accountLocks[i].policyId == policyId) {
                return accountLocks[i].amount;
            }
        }
        return 0;
    }

    /// @dev Ensures the policy cannot keep anything locked past the lock
    ///      sunset. Ending exactly at the sunset is allowed: the curve has
    ///      fully released and the hold has lapsed at that moment, which is
    ///      also when the sunset takes effect.
    function _validatePolicyMaturity(LockPolicy calldata policy) internal view {
        Curve calldata curve = policy.unlock;
        // The curve validation guarantees cliff <= vest when vest != 0, so
        // the curve fully releases at cliff (vest == 0) or at vest end.
        uint256 curveEnd = curve.vestDuration == 0
            ? curve.cliffDuration
            : curve.vestDuration;

        uint256 policyEnd = curve.anchor == Anchor.Tge
            ? uint256(CCA_END) + TGE_COOLDOWN + curveEnd
            : curve.start + curveEnd;

        if (policyEnd > NO_MORE_LOCKS) {
            revert InvalidPolicy();
        }
        if (policy.holdUntil > NO_MORE_LOCKS) {
            revert InvalidPolicy();
        }
    }

    /// @dev Validates the unlock curve: it must lock something and be
    ///      consistent with its anchor mode.
    function _validateCurve(Curve calldata curve) internal pure {
        if (curve.cliffDuration == 0 && curve.vestDuration == 0) {
            revert InvalidPolicy();
        }
        if (curve.anchor == Anchor.Absolute && curve.start == 0) {
            revert InvalidPolicy();
        }
        if (curve.anchor == Anchor.Tge && curve.start != 0) {
            revert InvalidPolicy();
        }
        // A cliff past the vest end would be a disguised step function.
        if (
            curve.vestDuration != 0 && curve.cliffDuration > curve.vestDuration
        ) {
            revert InvalidPolicy();
        }
    }

    /// @dev Still-locked amount under `policy` at `timestamp`: everything
    ///      before {LockPolicy.holdUntil}; the unlock curve's remainder
    ///      after (the curve accrues through the hold, so the accrued
    ///      portion catches up the moment the hold lapses). Fails closed:
    ///      A TGE-anchored curve releases nothing while TGE is unset.
    function _lockedAmount(
        LockPolicy storage policy,
        uint256 amount,
        uint64 timestamp
    ) internal view returns (uint256) {
        if (timestamp < policy.holdUntil) return amount;

        Curve storage curve = policy.unlock;
        uint256 anchor;
        if (curve.anchor == Anchor.Tge) {
            anchor = tgeTimestamp;
        } else {
            anchor = curve.start;
        }

        if (anchor == 0 || timestamp < anchor + curve.cliffDuration) {
            return amount;
        }

        uint256 vestDuration = curve.vestDuration;
        if (vestDuration == 0 || timestamp >= anchor + vestDuration) {
            return 0;
        }
        return amount - (amount * (timestamp - anchor)) / vestDuration;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Required overrides
    // ─────────────────────────────────────────────────────────────────────────

    /// @inheritdoc ERC20Permit
    function nonces(
        address owner
    ) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    /// @notice EIP-6372 clock — block.timestamp, aligned with other Interfold
    ///         contracts.
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

    /**
     * @notice Synchronises AccessControl roles whenever Ownable2Step completes a
     *         transfer (i.e. when {acceptOwnership} is called by the pending owner).
     */
    function _transferOwnership(address newOwner) internal override {
        address previousOwner = owner();
        super._transferOwnership(newOwner);
        if (previousOwner != address(0)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, previousOwner);
            _revokeRole(MINTER_ROLE, previousOwner);
            _revokeRole(WHITELIST_ROLE, previousOwner);
            _revokeRole(LOCK_MANAGER_ROLE, previousOwner);
        }
        if (newOwner != address(0)) {
            _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
            _grantRole(MINTER_ROLE, newOwner);
            _grantRole(WHITELIST_ROLE, newOwner);
            _grantRole(LOCK_MANAGER_ROLE, newOwner);
        }
    }
}
