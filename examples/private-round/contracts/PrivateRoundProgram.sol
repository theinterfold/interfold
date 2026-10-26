// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IOpenVmReceiptVerifier } from "@interfold/contracts/contracts/interfaces/IOpenVmReceiptVerifier.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { OpenVmComputeProof } from "@interfold/contracts/contracts/lib/OpenVmComputeProof.sol";
import { IDataAvailabilityVerifier, IE3ProgramDataAvailability } from "@interfold/contracts/contracts/interfaces/IDataAvailabilityVerifier.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { IBidVerifier } from "./interfaces/IBidVerifier.sol";
import { IBidderGate } from "./interfaces/IBidderGate.sol";
import { RoundClearing } from "./libraries/RoundClearing.sol";
import { RoundConfig, Round, ROUND_LEVELS } from "./libraries/RoundConfig.sol";
import { RoundOutput } from "./libraries/RoundOutput.sol";

/// @title Sealed private round: an OTC sale of lots to at most 13 bidders, at one uniform price.
/// @notice A creator sells `lots` lots of `lot` sale-token base units each, on a grid of `levels`
/// prices. Every bidder wants exactly one lot. A bidder escrows the same amount `escrow` of the payment
/// token once, and encrypts a price step `b`: the highest price it accepts. The creator names a public
/// reserve step `reserveStep` and a minimum `minLots`. The FHE program adds the bids and tests, for
/// every step, whether at least `lots` counted bidders accept it, and whether at least `minLots`
/// accept the reserve. The committee decrypts only those tests and the version of the bid that each
/// bidder had counted. This contract reads the outcome from them:
///
/// - `NOT_MET`: fewer than `minLots` bidders accept the reserve. Everybody gets the escrow back.
/// - `UNDERSUBSCRIBED`: the reserve is met, but fewer than `lots` bidders accept it. Every counted
///   bidder at or above the reserve gets one lot at the reserve price.
/// - `SOLD_OUT`: `lots` or more bidders accept the clearing step `l*`, the highest such step. One
///   price `prices[l*]` for everybody. Nobody learns the demand curve or any bid.
/// - `ABORTED`: the output breaks a rule of `RoundOutput`. It is handled like `NOT_MET`.
///
/// Flow: the creator approves `supply = lot * lots` of the sale token to this contract, then requests
/// the E3 (`validate` pulls the supply). A bidder calls `deposit` (or a relayer calls `depositFor`
/// with a permit) and gets an index `i` (0 to 12). The bidder then sends the bid with `publishInput`:
/// two ciphertexts, the bid and a mask, which the bid proof covers. The contract gives the proof `i`,
/// the version and the public round parameters from storage, so a bidder cannot count in the slot of
/// another bidder or bid outside the grid. After the output is published, `clear` reads the outcome.
///
/// A sold-out round settles in two phases, because the contract does not know how many bidders are
/// above `l*` or at `l*`. Bidders above `l*` claim in phase 1, and each gets one lot. Bidders at `l*`
/// register in phase 2. After phase 2, `settleMarginal` gives the lots that the bidders above `l*` did
/// not claim to the registered bidders in the order of the bidder index (the order of the deposits),
/// one whole lot each. A lot is never split. The other registered bidders, and every other bidder,
/// get the escrow back.
///
/// A bidder is an address. It may bid up to `MAX_BIDS_PER_BIDDER` times (a bid and updates). A bid is
/// sent by the bidder, or by a relayer with the bidder's EIP-712 signature.
contract PrivateRoundProgram is IE3Program, IE3ProgramDataAvailability, IERC165, Ownable, EIP712 {
  using InternalLazyIMT for LazyIMTData;
  using SafeERC20 for IERC20;

  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  /// @notice The prefix of the configuration input. The program uses the same bytes.
  bytes public constant CONFIG_DOMAIN = "interfold-private-round-config-v1";
  uint8 public constant TREE_DEPTH = 20;
  /// @notice The price steps of the slot layout. A round uses the first `levels` of them.
  uint8 public constant LEVELS = ROUND_LEVELS;
  /// @notice The most bidders of a round. The output has 13 version slots.
  uint256 public constant MAX_BIDDERS = 13;
  /// @notice The most bids of one bidder: the first bid and two updates.
  uint32 public constant MAX_BIDS_PER_BIDDER = 3;
  /// @notice The most lots of a round.
  uint8 public constant MAX_LOTS = 12;
  /// @notice After `clear`, bidders above the clearing step claim during this time.
  uint256 public constant PHASE1_WINDOW = 2 days;
  /// @notice After phase 1, bidders at the clearing step register during this time.
  uint256 public constant PHASE2_WINDOW = 2 days;
  /// @notice How long a bidder can claim after `clear`. After it, the creator can sweep what is left.
  uint256 public constant CLAIM_WINDOW = 30 days;
  /// @notice The EIP-712 type of a relayed bid.
  bytes32 public constant BID_TYPEHASH = keccak256("Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)");
  uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// @dev The clearing of a round, stored by `clear`.
  struct Cleared {
    bool cleared;
    uint8 outcome;
    uint8 step;
    /// @dev Whether the creator swept the round.
    bool swept;
    /// @dev Whether the creator took the supply back (`withdrawSupply`, `sweep` or `refundSupply`).
    bool supplyReturned;
    /// @dev The last second of phase 1, of phase 2, and of the claim window. Full words: the code
    /// to read them is smaller than the code to unpack a short integer.
    uint256 phase1End;
    uint256 phase2End;
    uint256 claimDeadline;
    uint256 counted;
    /// @dev The bidders above the clearing step that claimed in phase 1.
    uint256 aboveClaimed;
    /// @dev The bidders at the clearing step that registered in phase 2.
    uint256 marginalRegistered;
    /// @dev Bit `i` is set when the bidder with the index `i` registered at the clearing step.
    uint256 marginalMask;
    /// @dev The depositors that were paid out (a claim or a settlement).
    uint256 claimedCount;
    uint256 pStar;
    /// @dev The sale tokens paid to claimants.
    uint256 tokensClaimed;
  }

  /// @dev What `publishInput` decodes from its `data`.
  struct BidInput {
    address bidder;
    bytes[] ciphertexts;
    bytes32[] ctCommitments;
    bytes32 bidCommitment;
    bytes proof;
    bytes gateProof;
    bytes signature;
  }

  IInterfold public interfold;
  IOpenVmReceiptVerifier public verifier;
  bytes32 public imageId;
  /// @notice Verifies the bid proof (`private_round_bid`).
  IBidVerifier public immutable bidVerifier;
  /// @notice Verifies the claim proof (`private_round_claim`).
  IBidVerifier public immutable claimVerifier;
  /// @notice The VK chain of the circuits the bid proof passes through.
  bytes32 public immutable vkAnchor;
  /// @notice Verifies the availability receipt of the ciphertext output.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;

  mapping(address => bool) public authorizedContracts;
  mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
  mapping(uint256 e3Id => LazyIMTData) public inputs;
  /// @notice The round of an E3. The prices are in `salePrices`.
  mapping(uint256 e3Id => Round) public sale;
  /// @notice The depositors of a round. The bidder `i` is `bidderAt(e3Id, i)`.
  mapping(uint256 e3Id => uint256) public bidderCount;
  mapping(uint256 e3Id => mapping(uint256 index => address)) public bidderAt;
  /// @dev `index + 1` of a depositor, 0 for an address that has not deposited.
  mapping(uint256 e3Id => mapping(address bidder => uint256)) private _indexPlusOne;
  /// @notice The bids of an address in a round. The next bid has the version `bidCount + 1`.
  mapping(uint256 e3Id => mapping(address bidder => uint32)) public bidCount;
  /// @notice The `bidCommitment` of each version of a bidder's bid. The claim uses the counted one.
  mapping(uint256 e3Id => mapping(address bidder => mapping(uint32 version => bytes32))) public bidCommitments;
  mapping(uint256 e3Id => Cleared) private _cleared;
  /// @dev The counted version of bidder `i` in bits `2i` and `2i + 1`.
  mapping(uint256 e3Id => uint256) private _countedPacked;
  /// @notice Whether the depositor was paid out: a claim, a settlement or a refund after a failed E3.
  mapping(uint256 e3Id => mapping(address bidder => bool)) public claimed;
  /// @notice Whether a bidder at the clearing step registered in phase 2.
  mapping(uint256 e3Id => mapping(address bidder => bool)) public registered;
  /// @notice The payments of the claims, not yet withdrawn by the creator.
  mapping(uint256 e3Id => uint256) public proceedsAvailable;

  error CallerNotAuthorized();
  error E3AlreadyInitialized();
  error E3DoesNotExist();
  error VerifierAddressZero();
  error InvalidDataAvailabilityVerifier();
  error InvalidImageId();
  error EmptyInputData();
  error InvalidBidShape();
  error InputDeadlineReached();
  error InvalidComputeContext();
  error DataAvailabilityHashMismatch(bytes32 expected, bytes32 actual);
  error BidderIsZero();
  error SenderNotBidder(address sender, address bidder);
  error InvalidSignature(address bidder);
  error BidderNotEligible(address bidder);
  error TooManyBidders();
  error TooManyBids(address bidder);
  error InvalidBidProof();
  error InvalidClaimProof();
  error AlreadyDeposited(address bidder);
  error NotDeposited(address bidder);
  error OutputNotPublished();
  error NotCleared();
  error AlreadyClaimed(address bidder);
  error AlreadyRegistered(address bidder);
  error NotRegistered(address bidder);
  error MarginalPhaseNotOpen(uint256 phase1End);
  error SettlementNotOpen(uint256 phase2End);
  error InvalidComparison(uint8 cmp);
  error NotCreator(address sender);
  error ClaimWindowClosed(uint256 deadline);
  error ClaimWindowOpen(uint256 deadline);
  error AlreadySwept();
  error NothingToWithdraw();
  error SupplyNotWithdrawable(uint8 outcome);
  error E3NotFailed();
  error AlreadyCleared();

  /// @notice A round was requested. The supply is in this contract.
  /// @dev `gate` is zero when anyone may bid. A gate publishes its own configuration (the allowlist gate emits `AllowlistSet`).
  event SaleCreated(
    uint256 indexed e3Id,
    address indexed creator,
    uint8 levels,
    uint256[ROUND_LEVELS] prices,
    address saleToken,
    address paymentToken,
    uint256 lot,
    uint8 lots,
    uint8 reserveStep,
    uint8 minLots,
    uint256 escrow,
    string title,
    address gate
  );
  /// @notice A bidder escrowed and got an index.
  event Deposited(uint256 indexed e3Id, address indexed bidder, uint256 index);
  /// @notice A bidder submitted a bid, or an update of it. The ciphertexts are published here once.
  /// The leaf of the bid ciphertext (role 0) is the leaf `firstLeaf` of the input tree; the leaf of the
  /// mask (role 1) is `firstLeaf + 1`. `index` is the bidder index.
  event BidSubmitted(
    uint256 indexed e3Id,
    address indexed bidder,
    uint32 version,
    uint256 index,
    uint256 firstLeaf,
    bytes[] ciphertexts,
    bytes32[] ctCommitments,
    bytes32 bidCommitment
  );
  /// @notice The round was cleared from the published plaintext. `outcome`: 0 not met, 1 undersubscribed,
  /// 2 sold out, 3 aborted. `step` is `l*` (sold out), the reserve step (undersubscribed) or 0.
  event SaleCleared(uint256 indexed e3Id, uint8 outcome, uint8 step, uint256 pStar, uint256 counted);
  /// @notice The windows of a cleared round. Bidders above `l*` claim until `phase1End`; bidders at `l*`
  /// register until `phase2End`; every claim ends at `claimDeadline`.
  event ClaimWindowOpened(uint256 indexed e3Id, uint256 phase1End, uint256 phase2End, uint256 claimDeadline);
  event Claimed(uint256 indexed e3Id, address indexed bidder, uint256 tokens, uint256 paid, uint256 refund);
  /// @notice A bidder at the clearing step registered in phase 2. `settleMarginal` pays it after phase 2.
  event MarginalRegistered(uint256 indexed e3Id, address indexed bidder);
  event ProceedsWithdrawn(uint256 indexed e3Id, address indexed creator, uint256 amount);
  /// @notice The creator took the whole supply of a round that sold nothing (not met or aborted).
  event SupplyWithdrawn(uint256 indexed e3Id, address indexed creator, uint256 amount);
  /// @notice The creator swept the round after the claim window: what was left of both tokens.
  event Swept(uint256 indexed e3Id, address indexed creator, uint256 saleTokens, uint256 paymentTokens);
  /// @notice The E3 failed: a bidder got the escrow back.
  event EscrowRefunded(uint256 indexed e3Id, address indexed bidder, uint256 amount);
  /// @notice The E3 failed: the creator got the supply back.
  event SupplyRefunded(uint256 indexed e3Id, address indexed creator, uint256 amount);

  /// @param _interfold The Interfold contract address
  /// @param _verifier The OpenVM receipt verifier address
  /// @param _imageId The receipt identity: `imageId()` of the OpenVM receipt verifier.
  /// @param _bidVerifier The generated verifier of `private_round_bid`
  /// @param _claimVerifier The generated verifier of `private_round_claim`
  /// @param _vkAnchor The anchor of `private_round_bid` (`circuits/target/vk_anchor.json`)
  /// @param _dataAvailabilityVerifier The verifier of the output's availability receipt
  constructor(
    IInterfold _interfold,
    IOpenVmReceiptVerifier _verifier,
    bytes32 _imageId,
    IBidVerifier _bidVerifier,
    IBidVerifier _claimVerifier,
    bytes32 _vkAnchor,
    IDataAvailabilityVerifier _dataAvailabilityVerifier
  ) Ownable(msg.sender) EIP712("PrivateRoundProgram", "1") {
    require(
      address(_verifier) != address(0) && address(_bidVerifier) != address(0) && address(_claimVerifier) != address(0),
      VerifierAddressZero()
    );
    require(address(_dataAvailabilityVerifier).code.length != 0, InvalidDataAvailabilityVerifier());
    require(_imageId == _verifier.imageId(), InvalidImageId());
    interfold = _interfold;
    verifier = _verifier;
    imageId = _imageId;
    bidVerifier = _bidVerifier;
    claimVerifier = _claimVerifier;
    vkAnchor = _vkAnchor;
    dataAvailabilityVerifier = _dataAvailabilityVerifier;
    authorizedContracts[address(_interfold)] = true;
  }

  /// @inheritdoc IERC165
  function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
    return
      interfaceId == type(IE3Program).interfaceId ||
      interfaceId == type(IE3ProgramDataAvailability).interfaceId ||
      interfaceId == type(IERC165).interfaceId;
  }

  // ---------------------------------------------------------------------------------------------
  // Request
  // ---------------------------------------------------------------------------------------------

  /// @inheritdoc IE3Program
  /// @dev `customParams` is `abi.encode(uint8 levels, uint256[16] prices, address saleToken, uint256 lot,
  /// uint8 lots, uint8 reserveStep, uint8 minLots, address paymentToken, string title, address gate,
  /// bytes gateConfig)`. `prices[levels..16]` must be zero. Interfold calls this inside `request`, and
  /// the requester is already set. The requester must have approved `lot * lots` of the sale token to
  /// this contract before the request: this function pulls it. With `gate == address(0)` anyone may bid
  /// and `gateConfig` must be empty.
  function validate(
    uint256 e3Id,
    uint256,
    bytes calldata e3ProgramParams,
    bytes calldata,
    bytes calldata customParams
  ) external returns (bytes32) {
    require(authorizedContracts[msg.sender] || msg.sender == owner(), CallerNotAuthorized());
    require(paramsHashes[e3Id] == bytes32(0), E3AlreadyInitialized());
    paramsHashes[e3Id] = keccak256(e3ProgramParams);
    bytes memory gateConfig = _initSale(e3Id, customParams);
    Round storage s = sale[e3Id];
    inputs[e3Id]._init(TREE_DEPTH);
    inputs[e3Id]._insert(configLeaf(s.levels, s.reserveStep, s.lots, s.minLots));
    IERC20(s.saleToken).safeTransferFrom(s.creator, address(this), s.supply);
    if (s.gate != address(0)) IBidderGate(s.gate).configure(e3Id, gateConfig);
    return ENCRYPTION_SCHEME_ID;
  }

  /// @dev Decodes, checks and stores the round of `e3Id`. `RoundConfig.init` emits `SaleCreated`.
  function _initSale(uint256 e3Id, bytes calldata customParams) private returns (bytes memory gateConfig) {
    gateConfig = RoundConfig.init(sale[e3Id], e3Id, customParams, interfold.getE3(e3Id).requester);
  }

  /// @notice The price of each step of the round of `e3Id`, zero from `levels`.
  function salePrices(uint256 e3Id) external view returns (uint256[ROUND_LEVELS] memory) {
    return sale[e3Id].prices;
  }

  // ---------------------------------------------------------------------------------------------
  // Deposit
  // ---------------------------------------------------------------------------------------------

  /// @notice Escrow the fixed amount and get a bidder index. The sender is the bidder. The bidder must
  /// have approved `sale.escrow` of the payment token to this contract.
  /// @param gateProof The proof of eligibility for the round's gate, or empty.
  function deposit(uint256 e3Id, bytes calldata gateProof) external {
    _deposit(e3Id, msg.sender, gateProof);
  }

  /// @notice Escrow for `bidder` with the bidder's EIP-2612 permit. Anyone may send it (a relayer).
  /// The permit must grant this contract `sale.escrow` of the payment token. A permit that someone
  /// else already used does not make the call fail, if the allowance is enough.
  function depositFor(uint256 e3Id, address bidder, bytes calldata gateProof, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    address token = sale[e3Id].paymentToken;
    if (token == address(0)) revert E3DoesNotExist();
    try IERC20Permit(token).permit(bidder, address(this), sale[e3Id].escrow, deadline, v, r, s) {} catch {}
    _deposit(e3Id, bidder, gateProof);
  }

  function _sale(uint256 e3Id) private view returns (Round storage s) {
    s = sale[e3Id];
    if (s.creator == address(0)) revert E3DoesNotExist();
  }

  function _deposit(uint256 e3Id, address bidder, bytes calldata gateProof) private {
    Round storage s = _sale(e3Id);
    if (bidder == address(0)) revert BidderIsZero();
    if (block.timestamp > interfold.getE3(e3Id).inputWindow[1]) revert InputDeadlineReached();
    if (_indexPlusOne[e3Id][bidder] != 0) revert AlreadyDeposited(bidder);
    if (s.gate != address(0) && !IBidderGate(s.gate).isEligible(e3Id, bidder, gateProof)) revert BidderNotEligible(bidder);
    uint256 index = bidderCount[e3Id];
    if (index >= MAX_BIDDERS) revert TooManyBidders();
    bidderCount[e3Id] = index + 1;
    bidderAt[e3Id][index] = bidder;
    _indexPlusOne[e3Id][bidder] = index + 1;
    IERC20(s.paymentToken).safeTransferFrom(bidder, address(this), s.escrow);
    emit Deposited(e3Id, bidder, index);
  }

  /// @notice Whether `bidder` has deposited in the round.
  function deposited(uint256 e3Id, address bidder) public view returns (bool) {
    return _indexPlusOne[e3Id][bidder] != 0;
  }

  /// @notice The index of a depositor, 0 to 12. It is 0 for an address that has not deposited: check `deposited`.
  function bidderIndex(uint256 e3Id, address bidder) public view returns (uint256) {
    uint256 indexPlusOne = _indexPlusOne[e3Id][bidder];
    return indexPlusOne == 0 ? 0 : indexPlusOne - 1;
  }

  // ---------------------------------------------------------------------------------------------
  // Bids
  // ---------------------------------------------------------------------------------------------

  /// @notice Leaf 0 of a round: the configuration input, hashed into the field. The program reads the
  /// public parameters from it, so the compute proof binds them through the input root.
  function configLeaf(uint8 levels, uint8 reserveStep, uint8 lots, uint8 minLots) public pure returns (uint256) {
    return uint256(keccak256(abi.encodePacked(CONFIG_DOMAIN, levels, reserveStep, lots, minLots))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The leaf of one ciphertext of a bid. The program computes the same value from the
  /// published bytes and the 25 bytes of metadata `bidder || uint40 version`. The two ciphertexts of a
  /// bid have the same metadata.
  /// @param ciphertextHash `keccak256` of the ciphertext bytes.
  /// @param commitment The SAFE commitment of the ciphertext, which the bid proof binds.
  function inputLeaf(bytes32 ciphertextHash, bytes32 commitment, address bidder, uint32 version) public pure returns (uint256) {
    return uint256(sha256(abi.encodePacked(ciphertextHash, commitment, bidder, uint40(version)))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The EIP-712 digest that a bidder signs to let a relayer send a bid.
  /// @param version The version the bid will get: `bidCount + 1`.
  /// @param inputsHash `keccak256(abi.encode(ctCommitments, bidCommitment, ciphertextHashes))`.
  function bidDigest(uint256 e3Id, address bidder, uint32 version, bytes32 inputsHash) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(BID_TYPEHASH, e3Id, bidder, version, inputsHash)));
  }

  /// @notice Submit a bid, or an update of the bidder's earlier bid. The bidder must have deposited.
  /// @param data `abi.encode(address bidder, bytes[] ciphertexts, bytes32[] ctCommitments, bytes32
  /// bidCommitment, bytes proof, bytes gateProof, bytes signature)`. There are two ciphertexts (the bid
  /// and the mask) and two commitments, in role order. With an empty `signature` the sender must be
  /// `bidder`. Otherwise `signature` is the bidder's EIP-712 signature (`bidDigest`), and anyone may send.
  function publishInput(uint256 e3Id, bytes memory data) external override {
    E3 memory e3 = interfold.getE3(e3Id);
    if (block.timestamp > e3.inputWindow[1]) revert InputDeadlineReached();
    BidInput memory bid;
    (bid.bidder, bid.ciphertexts, bid.ctCommitments, bid.bidCommitment, bid.proof, bid.gateProof, bid.signature) = abi.decode(
      data,
      (address, bytes[], bytes32[], bytes32, bytes, bytes, bytes)
    );
    Round storage s = _sale(e3Id);
    if (bid.ciphertexts.length != 2 || bid.ctCommitments.length != 2) revert InvalidBidShape();
    if (bid.bidder == address(0)) revert BidderIsZero();
    if (bid.ciphertexts[0].length == 0 || bid.ciphertexts[1].length == 0) revert EmptyInputData();
    uint256 indexPlusOne = _indexPlusOne[e3Id][bid.bidder];
    if (indexPlusOne == 0) revert NotDeposited(bid.bidder);
    uint32 version = bidCount[e3Id][bid.bidder] + 1;
    if (version > MAX_BIDS_PER_BIDDER) revert TooManyBids(bid.bidder);
    bytes32[] memory hashes = new bytes32[](2);
    hashes[0] = keccak256(bid.ciphertexts[0]);
    hashes[1] = keccak256(bid.ciphertexts[1]);

    _checkSender(e3Id, bid, version, hashes);
    if (s.gate != address(0) && !IBidderGate(s.gate).isEligible(e3Id, bid.bidder, bid.gateProof)) revert BidderNotEligible(bid.bidder);
    _verifyBidProof(e3Id, bid, s, indexPlusOne - 1, version, e3.committeePublicKey);

    bidCount[e3Id][bid.bidder] = version;
    bidCommitments[e3Id][bid.bidder][version] = bid.bidCommitment;
    uint256 firstLeaf = inputs[e3Id].numberOfLeaves;
    inputs[e3Id]._insert(inputLeaf(hashes[0], bid.ctCommitments[0], bid.bidder, version));
    inputs[e3Id]._insert(inputLeaf(hashes[1], bid.ctCommitments[1], bid.bidder, version));
    emit BidSubmitted(e3Id, bid.bidder, version, indexPlusOne - 1, firstLeaf, bid.ciphertexts, bid.ctCommitments, bid.bidCommitment);
  }

  /// @dev A direct bid comes from its bidder. A relayed bid carries the bidder's signature over the
  /// version and the hash of the exact commitments and ciphertexts, so a relayer cannot swap bytes
  /// and an old signature is useless once the bidder has bid again.
  function _checkSender(uint256 e3Id, BidInput memory bid, uint32 version, bytes32[] memory hashes) private view {
    if (bid.signature.length == 0) {
      if (bid.bidder != msg.sender) revert SenderNotBidder(msg.sender, bid.bidder);
      return;
    }
    bytes32 inputsHash = keccak256(abi.encode(bid.ctCommitments, bid.bidCommitment, hashes));
    if (!SignatureChecker.isValidSignatureNow(bid.bidder, bidDigest(e3Id, bid.bidder, version, inputsHash), bid.signature)) {
      revert InvalidSignature(bid.bidder);
    }
  }

  /// @dev Public inputs of `private_round_bid`: `ct_commitment_bid, ct_commitment_mask, bid_commitment,
  /// bidder, e3_id, levels, reserve_step, bidder_index, version, pk_commitment, vk_anchor`. See
  /// `circuits/PUBLIC_INPUTS.md`.
  function _verifyBidProof(
    uint256 e3Id,
    BidInput memory bid,
    Round storage s,
    uint256 index,
    uint32 version,
    bytes32 committeePublicKey
  ) private view {
    bytes32[] memory publicInputs = new bytes32[](11);
    publicInputs[0] = bid.ctCommitments[0];
    publicInputs[1] = bid.ctCommitments[1];
    publicInputs[2] = bid.bidCommitment;
    publicInputs[3] = bytes32(uint256(uint160(bid.bidder)));
    publicInputs[4] = bytes32(e3Id);
    publicInputs[5] = bytes32(uint256(s.levels));
    publicInputs[6] = bytes32(uint256(s.reserveStep));
    publicInputs[7] = bytes32(index);
    publicInputs[8] = bytes32(uint256(version));
    publicInputs[9] = committeePublicKey;
    publicInputs[10] = vkAnchor;
    if (!bidVerifier.verify(bid.proof, publicInputs)) revert InvalidBidProof();
  }

  // ---------------------------------------------------------------------------------------------
  // Clearing
  // ---------------------------------------------------------------------------------------------

  /// @notice Clear the round from the published plaintext. Anyone may call it once. `claim`,
  /// `withdrawSupply` and the views of the clearing need it: `claim` and `withdrawSupply` call it if
  /// nobody did. An output that breaks a rule of `RoundOutput` clears as `ABORTED`; it does not revert.
  function clear(uint256 e3Id) public {
    Cleared storage out = _cleared[e3Id];
    if (out.cleared) return;
    Round storage s = _sale(e3Id);
    bytes memory plaintext = interfold.getE3(e3Id).plaintextOutput;
    if (plaintext.length == 0) revert OutputNotPublished();
    uint256 counted;
    (out.outcome, out.step, counted, _countedPacked[e3Id]) = RoundOutput.decode(
      plaintext,
      RoundOutput.Params(s.levels, s.reserveStep, s.lots, s.minLots),
      bidderCount[e3Id],
      bidderAt[e3Id],
      bidCount[e3Id]
    );
    out.cleared = true;
    out.counted = counted;
    out.pStar = RoundClearing.pStar(s.prices, out.outcome, out.step, s.reserveStep);
    uint256 clearedAt = block.timestamp;
    out.phase1End = clearedAt + PHASE1_WINDOW;
    out.phase2End = clearedAt + PHASE1_WINDOW + PHASE2_WINDOW;
    out.claimDeadline = clearedAt + CLAIM_WINDOW;
    emit SaleCleared(e3Id, out.outcome, out.step, out.pStar, counted);
    emit ClaimWindowOpened(e3Id, out.phase1End, out.phase2End, out.claimDeadline);
  }

  /// @notice The clearing of the round, after `clear`.
  /// @return cleared Whether `clear` ran.
  /// @return outcome 0 not met, 1 undersubscribed, 2 sold out, 3 aborted.
  /// @return step `l*` (sold out), the reserve step (undersubscribed) or 0.
  /// @return pStar The uniform price per whole sale token, in payment-token base units; 0 if nothing sells.
  /// @return counted The number of counted bidders.
  /// @return phase1End The last second at which a bidder above `l*` can claim its lot.
  /// @return phase2End The last second at which a bidder at `l*` can register.
  /// @return claimDeadline The last second at which a bidder can claim; the creator can sweep after it.
  /// @return aboveClaimed The bidders above `l*` that claimed so far.
  /// @return marginalRegistered The bidders at `l*` that registered so far.
  function clearing(
    uint256 e3Id
  )
    external
    view
    returns (
      bool cleared,
      uint8 outcome,
      uint8 step,
      uint256 pStar,
      uint256 counted,
      uint256 phase1End,
      uint256 phase2End,
      uint256 claimDeadline,
      uint256 aboveClaimed,
      uint256 marginalRegistered
    )
  {
    Cleared storage out = _cleared[e3Id];
    return (
      out.cleared,
      out.outcome,
      out.step,
      out.pStar,
      out.counted,
      out.phase1End,
      out.phase2End,
      out.claimDeadline,
      out.aboveClaimed,
      out.marginalRegistered
    );
  }

  /// @notice The bidders at the clearing step that registered: bit `i` is set for the bidder with the index `i`.
  function marginalMask(uint256 e3Id) external view returns (uint16) {
    return uint16(_cleared[e3Id].marginalMask);
  }

  /// @notice Whether the creator swept the round.
  function swept(uint256 e3Id) external view returns (bool) {
    return _cleared[e3Id].swept;
  }

  /// @notice Whether the creator took the supply back: `withdrawSupply`, `sweep` or `refundSupply`.
  function supplyReturned(uint256 e3Id) external view returns (bool) {
    return _cleared[e3Id].supplyReturned;
  }

  /// @notice The version of the bid that was counted for `bidder`, 0 when it was dropped or never bid.
  /// Needs `clear`.
  function countedVersion(uint256 e3Id, address bidder) public view returns (uint8) {
    if (!_cleared[e3Id].cleared) revert NotCleared();
    uint256 indexPlusOne = _indexPlusOne[e3Id][bidder];
    if (indexPlusOne == 0) return 0;
    return uint8((_countedPacked[e3Id] >> (2 * (indexPlusOne - 1))) & 3);
  }

  // ---------------------------------------------------------------------------------------------
  // Claim
  // ---------------------------------------------------------------------------------------------

  /// @notice Whether `bidder` must prove how its private bid compares with the claim step, and the
  /// step `k` of that proof. No proof is needed when the bidder was not counted, when nothing sold
  /// (not met, aborted), or when the round is undersubscribed with the reserve at step 0. Needs `clear`.
  function claimRequirement(uint256 e3Id, address bidder) public view returns (bool proofNeeded, uint8 k) {
    if (countedVersion(e3Id, bidder) == 0) return (false, 0);
    Cleared storage out = _cleared[e3Id];
    return RoundClearing.claimStep(out.outcome, out.step, sale[e3Id].reserveStep);
  }

  /// @notice What a claim of `bidder` does now, when the claim proof shows the comparison `cmp` of the
  /// bid step and the claim step (0: `b < k`, 1: `b == k`, 2: `b > k`). Needs `clear`. The timing of
  /// the phases applies: an above bidder after phase 1, and a bidder at the step that did not register
  /// by the end of phase 2, get the refund class.
  /// @return class 0 refund, 1 full lot, 2 marginal registration.
  /// @return tokens The sale-token base units of the bidder.
  /// @return paid The payment-token base units of the price.
  /// @return refund The payment-token base units that go back to the bidder.
  /// @dev For class 2 the amounts are what `settleMarginal` pays: a whole lot when fewer than
  /// `R = lots - aboveClaimed` registered bidders have a lower index than `bidder`, else the whole
  /// escrow. Before the end of phase 2 they are provisional: more bidders can register, and more
  /// above bidders can claim. A bidder that has not registered yet is ranked as if it registered now.
  function previewClaim(
    uint256 e3Id,
    address bidder,
    uint8 cmp
  ) public view returns (uint8 class, uint256 tokens, uint256 paid, uint256 refund) {
    _requireDeposited(e3Id, bidder);
    if (cmp > 2) revert InvalidComparison(cmp);
    Cleared storage out = _cleared[e3Id];
    class = RoundClearing.classOf(out.outcome, sale[e3Id].reserveStep, countedVersion(e3Id, bidder) != 0, cmp);
    if (class == RoundClearing.CLASS_FULL && out.outcome == RoundClearing.SOLD_OUT && block.timestamp > out.phase1End) {
      class = RoundClearing.CLASS_REFUND;
    }
    if (class == RoundClearing.CLASS_MARGINAL && !registered[e3Id][bidder] && block.timestamp > out.phase2End) {
      class = RoundClearing.CLASS_REFUND;
    }
    (tokens, paid, refund) = _amounts(e3Id, class, bidder);
  }

  function _amounts(uint256 e3Id, uint8 class, address bidder) private view returns (uint256 tokens, uint256 paid, uint256 refund) {
    Round storage s = sale[e3Id];
    Cleared storage out = _cleared[e3Id];
    if (class == RoundClearing.CLASS_FULL) {
      tokens = s.lot;
    } else if (class == RoundClearing.CLASS_MARGINAL) {
      uint256 rank = RoundClearing.marginalRank(out.marginalMask, bidderIndex(e3Id, bidder));
      if (RoundClearing.marginalFilled(s.lots, out.aboveClaimed, rank)) tokens = s.lot;
    }
    paid = RoundClearing.cost(tokens, out.pStar, s.saleUnit);
    refund = s.escrow - paid;
  }

  /// @notice Pay a depositor the tokens and the refund of the clearing, or register a bidder at the
  /// clearing step. Anyone may send it; the funds go to `bidder`.
  /// - Not counted, not met, aborted: the whole escrow, no proof.
  /// - Undersubscribed: with the reserve at step 0 a counted bidder gets a lot, no proof. Otherwise the
  ///   proof has `k = reserveStep - 1`, and `cmp == 2` gets a lot.
  /// - Sold out: the proof has `k = l*`. `cmp == 2` gets a lot in phase 1 and the refund later.
  ///   `cmp == 1` registers in phase 2 (it reverts in phase 1) and `settleMarginal` pays it after phase 2;
  ///   without a registration it gets the refund. `cmp == 0` gets the refund.
  /// @param data `abi.encode(uint8 cmp, bytes proof)`, or empty when `claimRequirement` says no proof is needed.
  function claim(uint256 e3Id, address bidder, bytes calldata data) external {
    clear(e3Id);
    _requireDeposited(e3Id, bidder);
    if (claimed[e3Id][bidder]) revert AlreadyClaimed(bidder);
    if (registered[e3Id][bidder]) revert AlreadyRegistered(bidder);
    Cleared storage out = _cleared[e3Id];
    if (block.timestamp > out.claimDeadline) revert ClaimWindowClosed(out.claimDeadline);
    uint8 cmp;
    (bool proofNeeded, uint8 k) = claimRequirement(e3Id, bidder);
    if (proofNeeded) {
      bytes memory proof;
      (cmp, proof) = abi.decode(data, (uint8, bytes));
      if (cmp > 2) revert InvalidComparison(cmp);
      _verifyClaimProof(e3Id, bidder, bidCommitments[e3Id][bidder][countedVersion(e3Id, bidder)], k, cmp, proof);
    }
    (uint8 class, uint256 tokens, uint256 paid, uint256 refund) = previewClaim(e3Id, bidder, cmp);
    if (class == RoundClearing.CLASS_MARGINAL) {
      if (block.timestamp <= out.phase1End) revert MarginalPhaseNotOpen(out.phase1End);
      registered[e3Id][bidder] = true;
      out.marginalMask |= 1 << bidderIndex(e3Id, bidder);
      out.marginalRegistered++;
      emit MarginalRegistered(e3Id, bidder);
      return;
    }
    if (class == RoundClearing.CLASS_FULL && out.outcome == RoundClearing.SOLD_OUT) out.aboveClaimed++;
    _payOut(e3Id, bidder, tokens, paid, refund);
  }

  /// @notice After phase 2, pay a registered bidder at the clearing step. The `R = lots - aboveClaimed`
  /// lots that the bidders above `l*` did not claim go to the registered bidders in the order of the
  /// bidder index, one whole lot each: the bidder gets its lot if fewer than `R` registered bidders
  /// have a lower index, and the whole escrow back otherwise. Anyone may send it; the funds go to `bidder`.
  function settleMarginal(uint256 e3Id, address bidder) external {
    Cleared storage out = _cleared[e3Id];
    if (!out.cleared) revert NotCleared();
    if (claimed[e3Id][bidder]) revert AlreadyClaimed(bidder);
    if (!registered[e3Id][bidder]) revert NotRegistered(bidder);
    if (block.timestamp <= out.phase2End) revert SettlementNotOpen(out.phase2End);
    if (block.timestamp > out.claimDeadline) revert ClaimWindowClosed(out.claimDeadline);
    (uint256 tokens, uint256 paid, uint256 refund) = _amounts(e3Id, RoundClearing.CLASS_MARGINAL, bidder);
    _payOut(e3Id, bidder, tokens, paid, refund);
  }

  function _payOut(uint256 e3Id, address bidder, uint256 tokens, uint256 paid, uint256 refund) private {
    Round storage s = sale[e3Id];
    Cleared storage out = _cleared[e3Id];
    claimed[e3Id][bidder] = true;
    out.claimedCount++;
    out.tokensClaimed += tokens;
    proceedsAvailable[e3Id] += paid;
    if (tokens != 0) IERC20(s.saleToken).safeTransfer(bidder, tokens);
    if (refund != 0) IERC20(s.paymentToken).safeTransfer(bidder, refund);
    emit Claimed(e3Id, bidder, tokens, paid, refund);
  }

  /// @dev Public inputs of `private_round_claim`: `bid_commitment, bidder, e3_id, k, cmp`.
  function _verifyClaimProof(uint256 e3Id, address bidder, bytes32 bidCommitment, uint8 step, uint8 cmp, bytes memory proof) private view {
    bytes32[] memory publicInputs = new bytes32[](5);
    publicInputs[0] = bidCommitment;
    publicInputs[1] = bytes32(uint256(uint160(bidder)));
    publicInputs[2] = bytes32(e3Id);
    publicInputs[3] = bytes32(uint256(step));
    publicInputs[4] = bytes32(uint256(cmp));
    if (!claimVerifier.verify(proof, publicInputs)) revert InvalidClaimProof();
  }

  // ---------------------------------------------------------------------------------------------
  // Creator
  // ---------------------------------------------------------------------------------------------

  function _creatorSale(uint256 e3Id) private view returns (Round storage s) {
    s = sale[e3Id];
    if (msg.sender != s.creator) revert NotCreator(msg.sender);
  }

  function _requireDeposited(uint256 e3Id, address bidder) private view {
    if (_indexPlusOne[e3Id][bidder] == 0) revert NotDeposited(bidder);
  }

  /// @notice The creator takes the payments of the claims so far. The payments of the bidders that
  /// did not claim yet are still in the contract.
  function withdrawProceeds(uint256 e3Id) external {
    Round storage s = _creatorSale(e3Id);
    uint256 amount = proceedsAvailable[e3Id];
    if (amount == 0) revert NothingToWithdraw();
    proceedsAvailable[e3Id] = 0;
    IERC20(s.paymentToken).safeTransfer(s.creator, amount);
    emit ProceedsWithdrawn(e3Id, s.creator, amount);
  }

  /// @notice The creator takes the whole supply of a round that sold nothing (not met or aborted). Once.
  /// A round that sells keeps its supply in the contract: the winners claim from it, and the creator
  /// takes what is left with `sweep`.
  function withdrawSupply(uint256 e3Id) external {
    Round storage s = _creatorSale(e3Id);
    clear(e3Id);
    Cleared storage out = _cleared[e3Id];
    if (out.outcome != RoundClearing.NOT_MET && out.outcome != RoundClearing.ABORTED) revert SupplyNotWithdrawable(out.outcome);
    if (out.supplyReturned) revert NothingToWithdraw();
    out.supplyReturned = true;
    IERC20(s.saleToken).safeTransfer(s.creator, s.supply);
    emit SupplyWithdrawn(e3Id, s.creator, s.supply);
  }

  /// @notice After the claim window, the creator takes everything that is still held for the round: the
  /// sale tokens that nobody claimed (unsold lots, forfeited lots, rounding), the escrows of bidders that
  /// were not paid out, and the payments that the creator did not take yet. Once. It moves only the
  /// amounts of this round, which the contract counts per round.
  function sweep(uint256 e3Id) external {
    Round storage s = _creatorSale(e3Id);
    Cleared storage out = _cleared[e3Id];
    if (!out.cleared) revert NotCleared();
    if (block.timestamp <= out.claimDeadline) revert ClaimWindowOpen(out.claimDeadline);
    if (out.swept) revert AlreadySwept();
    out.swept = true;
    // Sale tokens: the supply minus what claimants got, unless the creator took the whole supply already.
    uint256 saleTokens = out.supplyReturned ? 0 : s.supply - out.tokensClaimed;
    // Payment tokens: one escrow for each depositor that was not paid out, and the payments not yet withdrawn.
    uint256 paymentTokens = (bidderCount[e3Id] - out.claimedCount) * s.escrow + proceedsAvailable[e3Id];
    out.supplyReturned = true;
    proceedsAvailable[e3Id] = 0;
    if (saleTokens != 0) IERC20(s.saleToken).safeTransfer(s.creator, saleTokens);
    if (paymentTokens != 0) IERC20(s.paymentToken).safeTransfer(s.creator, paymentTokens);
    emit Swept(e3Id, s.creator, saleTokens, paymentTokens);
  }

  // ---------------------------------------------------------------------------------------------
  // Failed E3
  // ---------------------------------------------------------------------------------------------

  /// @notice The E3 failed, so there is no output: a depositor takes the escrow back.
  function refundEscrow(uint256 e3Id, address bidder) external {
    _requireFailed(e3Id);
    _requireDeposited(e3Id, bidder);
    if (claimed[e3Id][bidder]) revert AlreadyClaimed(bidder);
    claimed[e3Id][bidder] = true;
    Round storage s = sale[e3Id];
    IERC20(s.paymentToken).safeTransfer(bidder, s.escrow);
    emit EscrowRefunded(e3Id, bidder, s.escrow);
  }

  /// @notice The E3 failed, so there is no output: the creator takes the supply back.
  function refundSupply(uint256 e3Id) external {
    _requireFailed(e3Id);
    Round storage s = _creatorSale(e3Id);
    Cleared storage out = _cleared[e3Id];
    if (out.supplyReturned) revert NothingToWithdraw();
    out.supplyReturned = true;
    IERC20(s.saleToken).safeTransfer(s.creator, s.supply);
    emit SupplyRefunded(e3Id, s.creator, s.supply);
  }

  function _requireFailed(uint256 e3Id) private view {
    _sale(e3Id);
    if (_cleared[e3Id].cleared) revert AlreadyCleared();
    if (interfold.getE3Stage(e3Id) != IInterfold.E3Stage.Failed) revert E3NotFailed();
  }

  // ---------------------------------------------------------------------------------------------
  // Compute proof
  // ---------------------------------------------------------------------------------------------

  /// @notice Verify the compute proof
  /// @param e3Id The E3 program ID
  /// @param ciphertextOutputHash The hash of the ciphertext output
  /// @param ciphertextCommitment The proof-derived SAFE commitment
  /// @param proof The proof to verify
  function verify(
    uint256 e3Id,
    bytes32 ciphertextOutputHash,
    bytes32 ciphertextCommitment,
    bytes memory proof
  ) external view override returns (bool) {
    require(paramsHashes[e3Id] != bytes32(0), E3DoesNotExist());
    E3 memory e3 = interfold.getE3(e3Id);
    bytes32 paramsHash = paramsHashes[e3Id];
    bytes32 inputRoot = bytes32(inputs[e3Id]._root());
    OpenVmComputeProof.Proof memory computeProof = OpenVmComputeProof.decode(proof);
    if (computeProof.paramsHash != paramsHash || computeProof.inputRoot != inputRoot) revert InvalidComputeContext();
    bytes memory journal = OpenVmComputeProof.journal(
      bytes32(block.chainid),
      bytes32(uint256(uint160(address(interfold)))),
      bytes32(e3Id),
      e3.encryptionSchemeId,
      e3.committeePublicKey,
      ciphertextOutputHash,
      ciphertextCommitment,
      paramsHash,
      inputRoot
    );
    verifier.verify(computeProof.seal, imageId, sha256(journal));
    return true;
  }

  /// @notice Verify the availability receipt of the ciphertext output for Interfold.
  /// @dev Interfold checks the returned content hash again before it records the reference.
  function verifyDataAvailability(
    bytes32 expectedContentHash,
    bytes calldata proof
  ) external view override returns (IDataAvailabilityVerifier.DataReference memory receipt) {
    receipt = dataAvailabilityVerifier.verifyDataAvailability(expectedContentHash, proof);
    if (receipt.contentHash != expectedContentHash) {
      revert DataAvailabilityHashMismatch(expectedContentHash, receipt.contentHash);
    }
  }
}
