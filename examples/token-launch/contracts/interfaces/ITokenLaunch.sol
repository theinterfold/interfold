// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @title The public surface of `TokenLaunchProgram`: types, events, errors and functions.
/// @notice A sale is two E3s of one requester. E3-1 (round 1) has the id of the sale (`saleId`), E3-2
/// (round 2) is linked to it. A bid is one `publishInput` call on `saleId`. Every `saleId` argument
/// below is the E3 id of round 1. The libraries of the program revert with the errors of this interface.
interface ITokenLaunch {
  // ---------------------------------------------------------------------------------------------
  // Types
  // ---------------------------------------------------------------------------------------------

  /// @notice The state of a sale. `Aborted` and `Failed` allow the refunds; `Cleared` allows claims.
  /// - Bidding: the input window of the sale is open.
  /// - Round1: the window closed, round 1 has no plaintext yet.
  /// - Probing: round 1 has its plaintext, `publishProbes` did not run yet.
  /// - Round2: probes are published, round 2 has no plaintext yet.
  /// - Clearable: round 2 has its plaintext, `clear` did not run yet.
  enum Phase {
    None,
    Bidding,
    Round1,
    Probing,
    Round2,
    Clearable,
    Cleared,
    Aborted,
    Failed
  }

  /// @notice Why a sale aborted.
  enum AbortReason {
    None,
    NoRoundTwo,
    InvalidRound1Output,
    InvalidRound2Output,
    CountedSetMismatch
  }

  /// @notice The fixed part of a sale, from the role-1 `customParams`.
  /// @dev `saleUnit` is `10^decimals` of the sale token. A budget unit is `budgetUnit` payment-token base units.
  struct SaleInfo {
    address creator;
    uint8 levels;
    address saleToken;
    address paymentToken;
    uint256 supply;
    uint256 budgetUnit;
    uint256 saleUnit;
    string title;
  }

  /// @notice What a bidder (or a relayer) passes to `publishInput` as `abi.encode(BidInput)`.
  struct BidInput {
    address bidder;
    uint8 tier;
    bytes ciphertext1;
    bytes ciphertext2;
    bytes32 ctCommitment1;
    bytes32 ctCommitment2;
    bytes32 bidCommitment;
    bytes proof;
    /// @dev Empty for a direct bid (`msg.sender == bidder`). Otherwise the bidder's EIP-712 signature (`bidDigest`).
    bytes signature;
    /// @dev The EIP-2612 permit of the escrow, used when `signature` is not empty. A failing permit does not revert.
    uint256 permitDeadline;
    uint8 v;
    bytes32 r;
    bytes32 s;
  }

  /// @notice What a relayer passes to `claim` as `abi.encode(ClaimData)`.
  struct ClaimData {
    bytes proof;
    bytes32 nullifier;
    address recipient;
    uint16 escrowUnits;
    uint16 budgetUnits;
    uint8 cmp;
    /// @dev 0, except for a marginal claim in the marginal window (capped sale, `cmp == 1`): the bid index plus
    /// one, which the proof publishes. Such a claim only registers; `payMarginal` pays it after the window.
    uint8 indexPlusOne;
  }

  /// @notice The clearing of a sale. `kind`: 0 undersubscribed, 1 capped, 2 uncapped.
  /// @dev `step` is the step `k` of the claim proof. `remaining` is `R` of the capped case: the sale tokens that the
  /// bids at the clearing step share, first bid first (0 otherwise). `countedMask` has bit `i` set when bid `i` was
  /// counted. `marginalDeadline` is the end of the marginal window (capped sales; equal to `clear` time otherwise).
  struct ClearingInfo {
    bool cleared;
    uint8 kind;
    uint8 step;
    uint64 marginalDeadline;
    uint64 claimDeadline;
    uint256 pStar;
    uint256 sold;
    uint256 remaining;
    uint256 countedMask;
    uint256 root;
  }

  // ---------------------------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------------------------

  /// @notice A sale was requested (round 1). The supply is in the program.
  event SaleCreated(
    uint256 indexed saleId,
    address indexed creator,
    uint8 levels,
    uint256[16] prices,
    address saleToken,
    address paymentToken,
    uint256 supply,
    uint256 budgetUnit,
    uint16[4] tiers,
    string title
  );
  /// @notice Round 2 was requested and linked to the sale.
  event RoundTwoLinked(uint256 indexed saleId, uint256 indexed e3Id2);
  /// @notice A bid. The ciphertext of round 1 is leaf `index + 1` of the input tree of the sale, the ciphertext of
  /// round 2 is leaf `index + 1` of the input tree of round 2 and `bidCommitment` is leaf `index` of the claim tree.
  event BidSubmitted(
    uint256 indexed saleId,
    address indexed bidder,
    uint256 index,
    uint8 tier,
    bytes ciphertext1,
    bytes ciphertext2,
    bytes32 ctCommitment1,
    bytes32 ctCommitment2,
    bytes32 bidCommitment
  );
  /// @notice Round 1 is decoded. `config` is the input 0 of round 2 (role 2, `probeMask2`).
  event ProbesPublished(uint256 indexed saleId, uint256 indexed e3Id2, uint8 lo, uint8 hi, uint16 probeMask2, bytes config);
  /// @notice The sale is cleared. `knownMask` has bit `l` set for the levels with a revealed sum in `sums` (budget units).
  event SaleCleared(
    uint256 indexed saleId,
    uint8 kind,
    uint8 step,
    uint256 pStar,
    uint256 sold,
    uint256 countedMask,
    uint16 knownMask,
    uint256[16] sums
  );
  /// @notice The sale cannot clear. The bidders and the creator take their funds back.
  event SaleAborted(uint256 indexed saleId, AbortReason reason);
  /// @notice A claim. It names neither the bidder nor the bid index.
  event Claimed(uint256 indexed saleId, bytes32 indexed nullifier, address indexed recipient, uint256 tokens, uint256 paid, uint256 refund);
  /// @notice A marginal claim registered (capped sale, bid at the clearing step, inside the marginal window). It
  /// publishes the bid index, the budget and the recipient.
  event MarginalRegistered(uint256 indexed saleId, uint256 indexed index, uint16 budgetUnits, address recipient);
  event MarginalPaid(
    uint256 indexed saleId,
    uint256 indexed index,
    address indexed recipient,
    uint256 tokens,
    uint256 paid,
    uint256 refund
  );
  event DroppedRefunded(uint256 indexed saleId, uint256 indexed index, address indexed bidder, uint256 amount);
  event EscrowRefunded(uint256 indexed saleId, uint256 indexed index, address indexed bidder, uint256 amount);
  event SupplyRefunded(uint256 indexed saleId, address indexed creator, uint256 amount);
  event ForfeitedWithdrawn(uint256 indexed saleId, address indexed creator, uint256 amount);
  event ProceedsWithdrawn(uint256 indexed saleId, address indexed creator, uint256 amount);
  event UnsoldWithdrawn(uint256 indexed saleId, address indexed creator, uint256 amount);
  event Swept(uint256 indexed saleId, address indexed creator, uint256 saleTokens, uint256 paymentTokens);

  // ---------------------------------------------------------------------------------------------
  // Errors
  // ---------------------------------------------------------------------------------------------

  // Request (`validate`)
  error CallerNotAuthorized();
  error E3AlreadyInitialized();
  error E3DoesNotExist();
  error InvalidRole(uint8 role);
  error InvalidLevels();
  error InvalidPrices();
  error InvalidTiers();
  error InvalidAmount();
  error InvalidToken();
  error InvalidTitle();
  error InvalidRoundTwo();
  error RoundTwoAlreadyLinked(uint256 saleId);
  error RoundTwoMismatch();
  // Setup of the program
  error VerifierAddressZero();
  error InvalidDataAvailabilityVerifier();
  error InvalidImageId();
  error DataAvailabilityHashMismatch(bytes32 expected, bytes32 actual);
  error InvalidComputeContext();
  error ProbesNotPublished();
  // Bids
  error NotASale(uint256 e3Id);
  error RoundTwoNotLinked();
  error KeyNotPublished();
  error InputDeadlineReached();
  error EmptyInputData();
  error BidderIsZero();
  error TooManyBidders();
  error AlreadyBid(address bidder);
  error InvalidTier(uint8 tier);
  error InvalidBidCommitment();
  error SenderNotBidder(address sender, address bidder);
  error InvalidSignature(address bidder);
  error InvalidBidProof();
  // Rounds
  error WrongPhase(Phase phase);
  error OutputNotPublished();
  // Claims
  error InvalidClaimProof();
  error InvalidClaim();
  error NullifierUsed(bytes32 nullifier);
  error ClaimWindowClosed(uint256 deadline);
  error ClaimWindowOpen(uint256 deadline);
  error NotCleared();
  error MarginalWindowOpen(uint256 deadline);
  error NotRegistered(uint256 index);
  error AlreadyRegistered(uint256 index);
  error AlreadyPaid(uint256 index);
  // Refunds and the creator
  error NotCreator(address sender);
  error InvalidBidIndex(uint256 index);
  error NotDropped(uint256 index);
  error AlreadyRefunded(uint256 index);
  error Forfeited(uint256 index);
  error AlreadySwept();
  error NothingToWithdraw();

  // ---------------------------------------------------------------------------------------------
  // Reads
  // ---------------------------------------------------------------------------------------------

  function getSale(uint256 saleId) external view returns (SaleInfo memory);

  /// @notice The E3 id of round 2, 0 when it is not linked yet (E3 id 0 is never a round 2).
  function roundTwo(uint256 saleId) external view returns (uint256);

  /// @notice The price of each step: payment-token base units per `saleUnit` sale-token base units. 0 from `levels`.
  function salePrices(uint256 saleId) external view returns (uint256[16] memory);

  /// @notice The escrow tiers in budget units, ascending. Trailing zeros are unused tiers.
  function saleTiers(uint256 saleId) external view returns (uint16[4] memory);

  function bidCount(uint256 saleId) external view returns (uint256);

  function bidderAt(uint256 saleId, uint256 index) external view returns (address);

  /// @return bidder The sender of the bid.
  /// @return tier The escrow tier of the bid.
  /// @return commitment The `bidCommitment`: leaf `index` of the claim tree.
  function bidInfo(uint256 saleId, uint256 index) external view returns (address bidder, uint8 tier, bytes32 commitment);

  function phase(uint256 saleId) external view returns (Phase);

  /// @notice The probe search of round 1. `sums1` are budget-unit sums at the levels of `probeMask1`, 0 elsewhere.
  /// All are 0 before `publishProbes`.
  function probeInfo(
    uint256 saleId
  ) external view returns (uint8 lo, uint8 hi, uint16 probeMask1, uint16 probeMask2, uint256[16] memory sums1);

  function clearing(uint256 saleId) external view returns (ClearingInfo memory);

  /// @notice The root of the claim tree: the stored one after `clear`, the live one before.
  function claimRoot(uint256 saleId) external view returns (uint256);

  /// @notice What a claim pays for a claim proof with `cmp`, `budgetUnits` and `escrowUnits`. Needs `clear`. A
  /// marginal claim (`cmp == 1` in a capped sale) pays the refund only here: it is the claim after the marginal window.
  function previewClaim(
    uint256 saleId,
    uint8 cmp,
    uint16 budgetUnits,
    uint16 escrowUnits
  ) external view returns (uint256 tokens, uint256 paid, uint256 refund);

  /// @notice The marginal claim of bid `index`: whether it registered, its budget, its recipient and whether it was paid.
  function marginalInfo(
    uint256 saleId,
    uint256 index
  ) external view returns (bool registered, uint16 budgetUnits, address recipient, bool paid);

  /// @notice What `payMarginal` pays for the registered bid `index`: first bid first over the registered claims.
  /// All 0 when `index` did not register.
  function previewMarginal(uint256 saleId, uint256 index) external view returns (uint256 tokens, uint256 paid, uint256 refund);

  function nullifierUsed(uint256 saleId, bytes32 nullifier) external view returns (bool);

  function proceedsAvailable(uint256 saleId) external view returns (uint256);

  /// @notice The leaf of a bid ciphertext in an input tree. `index` is the bid index (the leaf is at `index + 1`).
  function leafOf(bytes32 ciphertextHash, bytes32 ctCommitment, address bidder, uint256 index) external pure returns (uint256);

  /// @notice The bytes of input 0 of an E3: `CONFIG_DOMAIN || role || levels || probeMask`.
  function configBytes(uint8 role, uint8 levels, uint16 probeMask) external pure returns (bytes memory);

  /// @notice Leaf 0 of an input tree: `keccak256(configBytes)` in the field.
  function configLeaf(uint8 role, uint8 levels, uint16 probeMask) external pure returns (uint256);

  /// @notice The EIP-712 digest a bidder signs to let a relayer send a bid.
  function bidDigest(uint256 saleId, address bidder, uint8 tier, bytes32 inputsHash) external view returns (bytes32);

  // ---------------------------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------------------------

  /// @notice Decode round 1 and fix the probes of round 2, or abort. Anyone, once round 1 has its plaintext.
  function publishProbes(uint256 saleId) external;

  /// @notice Decode round 2 and clear the sale, or abort. Anyone, once round 2 has its plaintext.
  function clear(uint256 saleId) external;

  /// @notice Pay a claim. Anyone may send it (a relayer): the funds go to `recipient`.
  /// @param data `abi.encode(ClaimData)`.
  function claim(uint256 saleId, bytes calldata data) external;

  /// @notice After the marginal window of a capped sale: pay the registered marginal claim of bid `index`. Anyone, once.
  function payMarginal(uint256 saleId, uint256 index) external;

  /// @notice After `clear`: the escrow of a bid that was not counted goes back to its bidder. Once.
  function refundDropped(uint256 saleId, uint256 index) external;

  /// @notice The sale failed or aborted: the escrow of a bid goes back to its bidder, unless it is forfeited. Once.
  function refundEscrow(uint256 saleId, uint256 index) external;

  /// @notice The sale failed or aborted: the creator takes the supply back. Once.
  function refundSupply(uint256 saleId) external;

  /// @notice The sale aborted on a counted-set mismatch: the creator takes the escrows of the forfeited bids. Once.
  function withdrawForfeited(uint256 saleId) external;

  function withdrawProceeds(uint256 saleId) external;

  /// @notice The creator takes the sale tokens that the clearing does not sell. Once.
  function withdrawUnsold(uint256 saleId) external;

  /// @notice After the claim window the creator takes all that the sale still holds. Once.
  function sweep(uint256 saleId) external;
}
