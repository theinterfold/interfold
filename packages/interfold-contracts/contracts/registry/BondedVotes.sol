// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IVotes } from "@openzeppelin/contracts/governance/utils/IVotes.sol";
import { IERC5805 } from "@openzeppelin/contracts/interfaces/IERC5805.sol";
import {
    IERC20Metadata
} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { IBondedCheckpoints } from "../interfaces/IBondedCheckpoints.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
// FOLD's lock schedule, the same surface the bonding registry reads. Lock-encumbered FOLD sits in
// the holder's own wallet and cannot be moved, so it can never be deposited into the escrow. The
// adapter can count this term only for live reads because the schedule is not checkpointed.
import {
    ILockAwareCiphernodeBondToken
} from "../interfaces/ILockAwareCiphernodeBondToken.sol";

/// @dev The slice of a voting-escrow IVotes adapter this contract needs to bind it to a token.
/// Only consulted when the votes source is not the token itself.
interface IEscrowVotesSource {
    function escrow() external view returns (address);
}

/// @dev The slice of a voting escrow this contract needs: what it custodies, and how much of it
/// it attributes to an account irrespective of delegation.
interface IVotingEscrow {
    function token() external view returns (address);

    function votingPowerForAccount(
        address account
    ) external view returns (uint256);
}

/**
 * @title BondedVotes
 * @notice Voting power that counts FOLD bonded as an operator alongside a primary vote source.
 *
 * @dev Bonding transfers FOLD to `BondingRegistry`, which never delegates it. Under ERC20Votes an
 * undelegated balance carries no voting power, so those votes are not moved to the registry —
 * they cease to exist. An operator therefore trades governance weight for the right to run a
 * ciphernode, and the more of the supply that is bonded, the harder any vote is to pass: bonded
 * FOLD still counts in `getPastTotalSupply`, so it raises the quorum denominator while being
 * unable to help meet it.
 *
 * This contract restores that weight by reading both sources at the same timepoint. It holds no
 * state and no privileges: it is a view over the token and the registry, so it can be deployed,
 * replaced or ignored without touching either.
 *
 * TWO TOKEN REFERENCES, ON PURPOSE. `token` is FOLD: it supplies the metadata and, critically,
 * the quorum DENOMINATOR. `votesSource` supplies the per-account NUMERATOR. They are separate
 * because the two questions have different answers under a lock-to-vote model:
 *
 *   votesSource == token          wallet-held FOLD votes, via the token's own ERC20Votes
 *                                 delegation. The original behaviour.
 *   votesSource == an escrow      only FOLD locked in the escrow votes. Idle wallet FOLD carries
 *                                 no weight, so holders must lock to participate — while
 *                                 operators keep their weight by bonding instead.
 *
 * Keeping the denominator on FOLD in both cases is what makes the ratio sound. Every unit the
 * numerator can produce — locked or bonded — is a FOLD that is still inside FOLD's total supply,
 * because locking and bonding both TRANSFER the token rather than burn it. So summed votes can
 * never exceed the supply they are measured against. Reading the denominator off the escrow
 * instead would omit the bonded half entirely and let participation exceed 100%.
 *
 * A THIRD SOURCE, under an escrow votes source only: current FOLD still encumbered by FOLD's own
 * vesting locks. That FOLD sits in the holder's own wallet and {InterfoldToken._update} refuses to
 * move it, so it can never reach the escrow. {getVotes} counts this live term so current voting
 * power can include token-level locks.
 *
 * {getPastVotes} does NOT count the token lock schedule. {lockedBalanceAt} walks the account's
 * current lock list, not a checkpointed history. A claim or link after a proposal snapshot can
 * otherwise increase voting power at that old snapshot.
 *
 * Escrowed and bonded FOLD cannot overlap: the escrow and the registry custody the token at two
 * different addresses, so the same token can never be at both. LOCKED AND BONDED DO OVERLAP, and
 * that is the one place a naive sum would go wrong. A bond satisfies a lock — see
 * {InterfoldToken.transferableBalanceOf}, which lets a wallet move its locked FOLD to the extent
 * the bond already covers the obligation — so an account that bonds its locked FOLD reports the
 * full amount under BOTH `lockedBalanceAt` and `getPastBonded` while holding it once. The locked
 * half is therefore netted down by the bond: what remains is the part the wallet must still be
 * holding, and `bonded + max(0, locked - bonded)` is just `max(bonded, locked)`.
 *
 * Delegation is deliberately not forwarded for the bonded part. `IVotes.delegate` here would have
 * to move a position the registry owns, which this contract cannot do. The primary source keeps
 * its own delegation, whatever that means for it.
 */
contract BondedVotes is IERC5805 {
    /// @notice The FOLD token. Supplies the metadata and the quorum denominator.
    IVotes public immutable token;

    /// @notice Where per-account voting power is read from: the token itself, or an escrow
    /// adapter when only locked FOLD may vote.
    IVotes public immutable votesSource;

    /// @notice The escrow behind `votesSource`, or zero when the votes source is the token.
    /// @dev Held so {balanceOf} can attribute locked FOLD without going through the adapter's
    /// own `balanceOf`, which counts lock NFTs rather than tokens.
    address public immutable escrow;

    /// @notice Records bonded totals over time for the registry holding bonded FOLD.
    IBondedCheckpoints public immutable checkpoints;

    /// @notice The registry that custodies the bonded FOLD and writes the history.
    address public immutable registry;

    /// @notice Thrown when a constructor argument is the zero address.
    error ZeroAddress();

    /// @notice Thrown when the token and the history do not agree on what a timepoint means.
    error ClockMismatch(uint48 tokenClock, uint48 checkpointsClock);

    /// @notice Thrown when the votes source measures a token other than the one being counted.
    error VotesSourceMismatch(address escrowToken, address votingToken);

    /// @notice Thrown when the history records bonds of a token other than the one read for votes.
    error TokenMismatch(address ciphernodeBondToken, address votingToken);

    /// @notice Thrown when an escrow votes source is paired with a token that has no lock
    /// schedule to read for live voting power.
    error LockedBalancesUnsupported(address votingToken);

    /// @notice Thrown for the delegation entry points, which this view cannot honour.
    error DelegationNotSupported();

    /**
     * @param _token The FOLD token: metadata, total supply, and the quorum denominator.
     * @param _votesSource Where per-account voting power is read. Pass `_token` itself to count
     * wallet-held FOLD, or an escrow IVotes adapter to count only locked FOLD.
     * @param _checkpoints The bonded-history contract.
     */
    constructor(
        IVotes _token,
        IVotes _votesSource,
        IBondedCheckpoints _checkpoints
    ) {
        if (address(_token) == address(0)) revert ZeroAddress();
        if (address(_votesSource) == address(0)) revert ZeroAddress();
        if (address(_checkpoints) == address(0)) revert ZeroAddress();

        // Checked once at deployment rather than on every read. Summing a timestamp-keyed history
        // with a block-numbered one would return a number for two unrelated points in time, and
        // nothing downstream could detect it.
        //
        // Compared by value rather than by `CLOCK_MODE()` string: two clocks that agree on the
        // current timepoint agree on every timepoint, and a block height cannot coincide with a
        // unix timestamp on any live chain. It also catches a clock that drifted for a reason no
        // mode string would describe.
        uint48 tokenClock = IERC5805(address(_token)).clock();
        uint48 registryClock = _checkpoints.clock();
        if (tokenClock != registryClock) {
            revert ClockMismatch(tokenClock, registryClock);
        }

        // The clock check proves the history speaks the same units as the token. It does not prove
        // the history is *about* this token. A checkpoint contract written by a registry that
        // custodies something else would add unbacked weight to this token's votes, and no reader
        // downstream could tell — summed voting power would simply exceed total supply. Binding
        // token, registry and history here is what makes that unrepresentable.
        //
        // A registry with no code fails this too: the call returns nothing and decoding reverts.
        address boundRegistry = _checkpoints.registry();
        address ciphernodeBondToken = IBondingRegistry(boundRegistry)
            .getCiphernodeBondToken();
        if (ciphernodeBondToken != address(_token)) {
            revert TokenMismatch(ciphernodeBondToken, address(_token));
        }

        token = _token;
        votesSource = _votesSource;
        escrow = _bindVotesSource(_token, _votesSource, tokenClock);
        checkpoints = _checkpoints;
        registry = boundRegistry;
    }

    /// @dev Checks a votes source may be summed with this token's history, and resolves the
    /// escrow behind it.
    ///
    /// Two conditions, for the same reason `TokenMismatch` exists on the other half of the
    /// numerator. The clock, because a block-numbered source summed with a timestamp-keyed
    /// history answers for two unrelated instants and nothing downstream could detect it. The
    /// custodied token, because an escrow over something else would mint voting power this
    /// token's supply does not back — the denominator would be FOLD while the numerator counted
    /// something else, and participation could exceed 100% with nothing able to notice.
    ///
    /// A votes source that IS the token is trivially about itself, needs no escrow, and returns
    /// zero here so {balanceOf} never consults one.
    /// @return The escrow behind the votes source, or zero when it is the token itself.
    function _bindVotesSource(
        IVotes _token,
        IVotes _votesSource,
        uint48 tokenClock
    ) private view returns (address) {
        if (address(_votesSource) == address(_token)) return address(0);

        uint48 votesClock = IERC5805(address(_votesSource)).clock();
        if (tokenClock != votesClock) {
            revert ClockMismatch(tokenClock, votesClock);
        }

        address boundEscrow = IEscrowVotesSource(address(_votesSource))
            .escrow();
        address escrowToken = IVotingEscrow(boundEscrow).token();
        if (escrowToken != address(_token)) {
            revert VotesSourceMismatch(escrowToken, address(_token));
        }

        // Probed once here rather than tolerated on every live read. Under an escrow votes source
        // the lock schedule is the only way an encumbered holder can report current voting power,
        // so a token that cannot answer for it must not be deployed against silently.
        (bool ok, bytes memory result) = address(_token).staticcall(
            abi.encodeCall(
                ILockAwareCiphernodeBondToken.lockedBalanceAt,
                (address(0), 0)
            )
        );
        if (!ok || result.length != 32) {
            revert LockedBalancesUnsupported(address(_token));
        }

        return boundEscrow;
    }

    /// @notice Get the current timepoint, in ERC-6372 clock units.
    /// @dev Delegated to the token so this adapter can never disagree with it about what a
    /// timepoint means. The constructor already established that the registry agrees too.
    /// @return Current timepoint.
    function clock() public view returns (uint48) {
        return IERC5805(address(token)).clock();
    }

    /// @notice Get the ERC-6372 description of this adapter's clock.
    /// @return Machine-readable clock mode, as reported by the token.
    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() external view returns (string memory) {
        return IERC5805(address(token)).CLOCK_MODE();
    }

    /// @inheritdoc IVotes
    /// @dev The historical numerator: whatever the primary source attributes to the account, plus
    /// its bonded FOLD. Both sources are checkpointed and read at the same timepoint. The token
    /// lock schedule is excluded because it is present-state, not checkpointed history.
    function getPastVotes(
        address account,
        uint256 timepoint
    ) external view returns (uint256) {
        uint256 bonded = checkpoints.getPastBonded(account, timepoint);

        return votesSource.getPastVotes(account, timepoint) + bonded;
    }

    /// @dev The live vesting-locked half of the numerator, netted down by the bond.
    ///
    /// Zero unless the votes source is an escrow. When the token votes for itself, locked FOLD is
    /// wallet FOLD and the token has already counted it — adding it again would simply double
    /// every locked holder's weight.
    ///
    /// Netted, because a bond satisfies a lock: FOLD that is bonded is reported by BOTH
    /// `lockedBalanceAt` and the bonded total while existing once, and the caller already counts
    /// the bonded side in full. What is left is the part of the obligation the wallet must still
    /// hold.
    ///
    /// This term is read only by {getVotes}. It is deliberately absent from {getPastVotes} because
    /// `lockedBalanceAt` walks the account's current locks, not a checkpointed history. A lock
    /// created after a governance snapshot can appear in that snapshot's answer. That violates the
    /// snapshot rule that past voting power must not change after the snapshot.
    ///
    /// Counting only PENDING would not be sufficient: a later `linkClaim` can move that PENDING
    /// amount into a real policy, and the token still has no per-lock creation timestamp. Until a
    /// checkpointed lock source exists, historical governance reads must use only the checkpointed
    /// votes source and bonded history.
    /// CAPPED at the wallet balance, because netting alone stops being enough once a bond can be
    /// SLASHED. What makes `locked - bonded` a real holding is the token's own transfer rule,
    /// `balance >= locked - bonded`, enforced on every transfer. Slashing cuts the bond without
    /// cutting the lock, so an operator that had already moved locked FOLD out on the strength of
    /// that bond is left owing more than it holds — and the uncapped term would vote with the
    /// difference, FOLD that is now in the slash recipient's hands and countable there too.
    ///
    /// The cap is a bound, never a source: the cap can only lower this term towards what the
    /// account demonstrably holds. The only power it can lower is the account's own.
    /// @param bonded The account's bonded total at the same timepoint.
    function _lockedVotes(
        address account,
        uint64 timestamp,
        uint256 bonded
    ) private view returns (uint256) {
        if (escrow == address(0)) return 0;

        uint256 locked = ILockAwareCiphernodeBondToken(address(token))
            .lockedBalanceAt(account, timestamp);
        if (locked <= bonded) return 0;

        uint256 unbonded = locked - bonded;
        uint256 held = IERC20Metadata(address(token)).balanceOf(account);

        return unbonded > held ? held : unbonded;
    }

    /// @inheritdoc IVotes
    /// @dev The denominator, and always the TOKEN's supply — never the votes source's. Bonded and
    /// locked FOLD are both already counted here: each was transferred, not burned. Adding either
    /// total again would double it and inflate every quorum denominator, and reading the escrow's
    /// supply instead would omit the bonded half and let participation exceed 100%. Leaving it
    /// alone is what makes the ratio sound in both configurations.
    function getPastTotalSupply(
        uint256 timepoint
    ) external view returns (uint256) {
        return token.getPastTotalSupply(timepoint);
    }

    /// @inheritdoc IVotes
    /// @dev Every half reads the present. Pairing a current wallet balance with
    /// `getPastBonded(account, clock() - 1)` would sum two different instants: a claim or a slash
    /// in this block would leave the bonded half stale and high, so the total could exceed what
    /// the owner holds — and, summed across owners, exceed total supply.
    function getVotes(address account) external view returns (uint256) {
        uint256 bonded = checkpoints.bonded(account);

        return
            votesSource.getVotes(account) +
            bonded +
            _lockedVotes(account, uint64(block.timestamp), bonded);
    }

    /// @inheritdoc IVotes
    /// @dev The primary source's delegate. Bonded weight is not delegatable, so it always sits
    /// with the bond owner regardless of what this returns.
    function delegates(address account) external view returns (address) {
        return votesSource.delegates(account);
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                  ERC-20 read surface                   //
    //                                                        //
    ////////////////////////////////////////////////////////////
    //
    // Read-only on purpose. `transfer`, `transferFrom`, `approve` and `allowance` are deliberately
    // absent: this contract owns no position and can move nothing, so a caller that tries to spend
    // through it reverts on a missing selector instead of believing a transfer happened.
    //
    // The read half exists because Aragon's plugin setups gate installation on a `balanceOf` probe
    // — `TokenVotingSetup._isERC20` staticcalls `balanceOf(address)` and rejects the token unless
    // it returns 32 bytes — and because the governance app reads the metadata to render amounts.

    /// @notice Get the FOLD attributable to an account: held in its wallet plus bonded under it.
    /// @dev Not a spendable balance, and nothing here can move it. Unlike {getVotes} this ignores
    /// delegation, so it answers "how much FOLD is this account's" rather than "how much can it
    /// vote with". A holder that never delegated reads a balance above its votes, which is the
    /// intended signal.
    ///
    /// The registry is netted down by what it merely custodies. Bonding moves FOLD into the
    /// registry while this contract attributes it to the bond owner, so counting it at both
    /// addresses would place the same tokens twice and push the summed balances above total
    /// supply — which is exactly what any holder-percentage view divides by. What remains for the
    /// registry is genuine surplus it holds on its own account.
    /// @param account The account to read.
    /// @return Attributable wallet balance plus bonded total.
    function balanceOf(address account) external view returns (uint256) {
        uint256 held = IERC20Metadata(address(token)).balanceOf(account);

        if (account == registry) {
            uint256 custodied = IBondingRegistry(registry)
                .totalCiphernodeBondLiability();
            // Saturating: an accounting drift must not make the balance unreadable.
            held = held > custodied ? held - custodied : 0;
        } else if (escrow != address(0) && account == escrow) {
            // The escrow is netted for the same reason as the registry, and to the same end:
            // every unit it holds is already attributed below to the account that locked it, so
            // leaving it here too would place the same FOLD at two addresses and push summed
            // balances past total supply.
            //
            // Netted to zero rather than by a liability figure, because the escrow exposes no
            // such total, and inventing one from an interface this contract cannot verify would
            // be the more dangerous guess. The cost is that FOLD donated to the escrow on its own
            // account reads as nothing; the alternative cost is a double count, and only one of
            // those breaks the denominator every holder-percentage view divides by.
            held = 0;
        }

        // Locked FOLD is custodied by the escrow for the same reason bonded FOLD is custodied by
        // the registry, so it is attributed to the locker here rather than left sitting with the
        // contract holding it. Read per-account and delegation-blind, matching what this function
        // means; the adapter's own `balanceOf` is deliberately not used, because it counts lock
        // NFTs rather than tokens.
        if (escrow != address(0)) {
            held += IVotingEscrow(escrow).votingPowerForAccount(account);
        }

        return held + checkpoints.bonded(account);
    }

    /// @notice Get the token's total supply.
    /// @dev Passed through for the same reason as {getPastTotalSupply}: bonded FOLD was
    /// transferred, not burned, so it is already counted and must not be added again.
    /// @return The token's total supply.
    function totalSupply() external view returns (uint256) {
        return IERC20Metadata(address(token)).totalSupply();
    }

    /// @notice Get the token's decimals.
    /// @return Decimals, as reported by the token.
    function decimals() external view returns (uint8) {
        return IERC20Metadata(address(token)).decimals();
    }

    /// @notice Get the token's name.
    /// @return Name, as reported by the token.
    function name() external view returns (string memory) {
        return IERC20Metadata(address(token)).name();
    }

    /// @notice Get the token's symbol.
    /// @return Symbol, as reported by the token.
    function symbol() external view returns (string memory) {
        return IERC20Metadata(address(token)).symbol();
    }

    /// @inheritdoc IVotes
    /// @dev Not supported. Delegate on the token directly — this contract owns no position and
    /// cannot move the registry's. Reverting rather than silently doing nothing, so a caller
    /// cannot believe it delegated bonded weight.
    function delegate(address) external pure {
        revert DelegationNotSupported();
    }

    /// @inheritdoc IVotes
    /// @dev Not supported, for the same reason as {delegate}.
    function delegateBySig(
        address,
        uint256,
        uint256,
        uint8,
        bytes32,
        bytes32
    ) external pure {
        revert DelegationNotSupported();
    }
}
