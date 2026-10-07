// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

/// @notice An open self-registration census for `CensusMode.ONCHAIN` rounds.
/// @dev Anyone may register themselves, once, and registration is permanent. The contract answers
/// the `IVotesToken` surface `CRISPProgram._eligibility` reads: `getPastVotes` returns 1 for a
/// registered account and 0 otherwise. Without `clock()` the round snapshot falls back to block
/// numbers; without `getPastTotalSupply` it serves `CreditMode.CONSTANT` rounds only.
///
/// `getPastVotes` deliberately ignores the timepoint. An honest checkpointed answer would fix the
/// electorate at the round's snapshot, which is taken in the transaction that requests the round —
/// before anyone knew there was a round to register for. Ignoring it is what lets a voter register
/// during the input window and vote in the same round. The cost is that the electorate is not
/// fixed per round: an input's eligibility depends on when it is published, not on one snapshot
/// every input shares. That is a deliberate trade for low-stakes polls.
///
/// Registration is open and unpriced, so one person can register any number of addresses. Use
/// this census only where one-address-one-vote is not worth attacking — a meme poll, a temperature
/// check — never where the outcome carries value. Pair it with `CreditMode.CONSTANT` and credits
/// of 1: every registrant carries the same weight, and `minVotingPower` of 1 is exactly what a
/// registered account reports.
///
/// Registrants are enumerable so mask submitters can draw a target: a mask is written to someone
/// else's slot, and without a public list of who is eligible there is nobody to mask. The list is
/// append-only, which keeps indices stable for random selection.
contract SelfRegistry {
  /// @notice One entry per registered account, in registration order. Append-only.
  address[] private _registrants;

  /// @notice Whether an account has registered.
  mapping(address account => bool) public isRegistered;

  /// @notice An account registered for voting.
  /// @param account The account that registered.
  /// @param index Its position in the registrant list.
  event Registered(address indexed account, uint256 index);

  /// @notice The account has already registered; registration is permanent and single-shot.
  error AlreadyRegistered(address account);

  /// @notice Register the caller as an eligible voter.
  /// @dev Permanent: there is no deregistration. Removing an entry would shift or hole the
  /// registrant list that mask submitters index into, and would let a voter provably leave the
  /// electorate mid-round — a slot that cannot be masked any more is a receipt.
  function register() external {
    if (isRegistered[msg.sender]) revert AlreadyRegistered(msg.sender);

    isRegistered[msg.sender] = true;
    _registrants.push(msg.sender);

    emit Registered(msg.sender, _registrants.length - 1);
  }

  /// @notice The voting power of an account: 1 when registered, 0 otherwise.
  /// @dev The timepoint is ignored — see the contract-level note. The parameter stays in the
  /// signature because `CRISPProgram` calls through `IVotesToken`.
  /// @param account The account to read.
  /// @return One for a registered account, zero otherwise.
  function getPastVotes(address account, uint256) external view returns (uint256) {
    return isRegistered[account] ? 1 : 0;
  }

  /// @notice How many accounts have registered.
  /// @return The registrant count.
  function totalRegistrants() external view returns (uint256) {
    return _registrants.length;
  }

  /// @notice The registrant at one index of the append-only list.
  /// @param index The position, in registration order.
  /// @return The registered account.
  function registrantAt(uint256 index) external view returns (address) {
    return _registrants[index];
  }

  /// @notice A page of the registrant list, for clients drawing mask targets.
  /// @dev Clamped rather than reverting past the end, so a caller can page with a fixed size and
  /// not race registrations between reading the count and reading the page.
  /// @param start The first index to read.
  /// @param count How many entries to read at most.
  /// @return page The registrants in `[start, min(start + count, total))`.
  function registrants(uint256 start, uint256 count) external view returns (address[] memory page) {
    uint256 total = _registrants.length;
    if (start >= total) return new address[](0);

    // Compared by subtraction, not by `start + count > total`: the addition runs under checked
    // arithmetic, so a large `count` would revert before the clamp it exists to trigger.
    // `total - start` cannot underflow — `start < total` is established above.
    uint256 end = count > total - start ? total : start + count;
    page = new address[](end - start);

    for (uint256 i = start; i < end; i++) {
      page[i - start] = _registrants[i];
    }
  }
}
