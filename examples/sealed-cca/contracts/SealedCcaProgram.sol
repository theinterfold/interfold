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
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { IERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { IBidVerifier } from "./interfaces/IBidVerifier.sol";
import { IBidderGate } from "./interfaces/IBidderGate.sol";
import { SaleClearing } from "./libraries/SaleClearing.sol";
import { SaleConfig, Sale, SALE_LEVELS } from "./libraries/SaleConfig.sol";
import { SaleOutput } from "./libraries/SaleOutput.sol";

/// @title Sealed-bid, one-batch, uniform-price token sale (a sealed continuous clearing auction).
/// @notice A creator sells `supply` of a sale token for a payment token on a grid of `levels` prices.
/// Every bidder escrows the same amount `escrow` of the payment token, and encrypts one number to the
/// E3 committee key: the step `b` of the highest price they accept. The FHE program adds the bids.
/// The committee decrypts only the demand curve `c[l]` (the bidders with `b >= l`) and the version
/// of the bid that each bidder had counted. This contract clears the sale on that curve: one price
/// for everybody. A bidder then claims with a proof of how their private `b` compares with the
/// clearing step, and gets tokens and a refund. Nobody sees `b` of any bidder.
///
/// Flow: the creator approves the sale token to this contract, then requests the E3 (`validate`
/// pulls `supply`). A bidder calls `deposit` (or a relayer calls `depositFor` with a permit): it
/// takes the escrow once and gives the bidder an index `i` (0 to 111). The bidder then sends the bid
/// with `publishInput`. The bid ciphertext holds the thermometer `m[l] = [l <= b]` in the slots 0 to
/// 15 and the version of the bid in slot `16 + i`. The bid proof shows this, and the contract gives
/// the proof `i` and the version from storage, so a bidder cannot count in the slot of another.
/// The sum of the counted ciphertexts decrypts to `c[0..15]` and, in slot `16 + i`, the version of
/// bidder `i` that was counted (0 if none). The decryption is verified on chain, so the contract
/// reads the counted set from it without extra trust.
///
/// A bidder is an address. It may bid up to `MAX_BIDS_PER_BIDDER` times (a bid and updates). A bid is
/// sent by the bidder, or by a relayer with the bidder's EIP-712 signature.
contract SealedCcaProgram is IE3Program, IE3ProgramDataAvailability, IERC165, Ownable, EIP712 {
  using InternalLazyIMT for LazyIMTData;
  using SafeERC20 for IERC20;

  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  /// @notice The prefix of the configuration input. The program uses the same bytes.
  bytes public constant CONFIG_DOMAIN = "interfold-sealed-cca-config-v1";
  uint8 public constant TREE_DEPTH = 20;
  /// @notice The price steps of the slot layout. A sale uses the first `levels` of them.
  uint8 public constant LEVELS = SALE_LEVELS;
  /// @notice The most bidders of a sale. The output has 128 slots: 16 for the curve, 112 for the bidders.
  uint256 public constant MAX_BIDDERS = 112;
  /// @notice The most bids of one bidder: the first bid and two updates.
  uint32 public constant MAX_BIDS_PER_BIDDER = 3;
  /// @notice How long a bidder can claim after `clear`. After it, the creator can sweep what is left.
  uint64 public constant CLAIM_WINDOW = 30 days;
  /// @notice The EIP-712 type of a relayed bid.
  bytes32 public constant BID_TYPEHASH = keccak256("Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)");
  uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// @dev The clearing of a sale, stored by `clear`.
  struct Cleared {
    bool cleared;
    uint8 kind;
    uint8 step;
    /// @dev The last second at which `claim` works: the time of `clear` plus `CLAIM_WINDOW`.
    uint64 claimDeadline;
    /// @dev Whether the creator swept the sale.
    bool swept;
    /// @dev The depositors that claimed.
    uint32 claimedCount;
    uint256 pStar;
    uint256 fullTokens;
    uint256 marginalTokens;
    uint256 sold;
    /// @dev The sale tokens paid to claimants.
    uint256 tokensClaimed;
  }

  /// @dev What `publishInput` decodes from its `data`.
  struct BidInput {
    address bidder;
    bytes ciphertext;
    bytes32 ctCommitment;
    bytes32 bidCommitment;
    bytes proof;
    bytes gateProof;
    bytes signature;
  }

  IInterfold public interfold;
  IOpenVmReceiptVerifier public verifier;
  bytes32 public imageId;
  /// @notice Verifies the bid proof (`sealed_cca_bid`).
  IBidVerifier public immutable bidVerifier;
  /// @notice Verifies the claim proof (`sealed_cca_claim`).
  IBidVerifier public immutable claimVerifier;
  /// @notice The VK chain of the circuits the bid proof passes through.
  bytes32 public immutable vkAnchor;
  /// @notice Verifies the availability receipt of the ciphertext output.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;

  mapping(address => bool) public authorizedContracts;
  mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
  mapping(uint256 e3Id => LazyIMTData) public inputs;
  mapping(uint256 e3Id => Sale) public sale;
  /// @notice The depositors of a sale. The bidder `i` is `bidderAt(e3Id, i)`.
  mapping(uint256 e3Id => uint256) public bidderCount;
  mapping(uint256 e3Id => mapping(uint256 index => address)) public bidderAt;
  /// @dev `index + 1` of a depositor, 0 for an address that has not deposited.
  mapping(uint256 e3Id => mapping(address bidder => uint256)) private _indexPlusOne;
  /// @notice The bids of an address in a sale. The next bid has the version `bidCount + 1`.
  mapping(uint256 e3Id => mapping(address bidder => uint32)) public bidCount;
  /// @notice The `bidCommitment` of each version of a bidder's bid. The claim uses the counted one.
  mapping(uint256 e3Id => mapping(address bidder => mapping(uint32 version => bytes32))) public bidCommitments;
  mapping(uint256 e3Id => Cleared) private _cleared;
  /// @dev The counted version of bidder `i` in bits `2i` and `2i + 1`.
  mapping(uint256 e3Id => uint256) private _countedPacked;
  mapping(uint256 e3Id => mapping(address bidder => bool)) public claimed;
  /// @notice The payments of the claims, not yet withdrawn by the creator.
  mapping(uint256 e3Id => uint256) public proceedsAvailable;
  mapping(uint256 e3Id => bool) public unsoldWithdrawn;
  mapping(uint256 e3Id => bool) public supplyRefunded;

  error CallerNotAuthorized();
  error E3AlreadyInitialized();
  error E3DoesNotExist();
  error VerifierAddressZero();
  error InvalidDataAvailabilityVerifier();
  error InvalidImageId();
  error EmptyInputData();
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
  error InvalidOutput();
  error NotCleared();
  error AlreadyClaimed(address bidder);
  error InvalidComparison(uint8 cmp);
  error NotCreator(address sender);
  error ClaimWindowClosed(uint256 deadline);
  error ClaimWindowOpen(uint256 deadline);
  error AlreadySwept();
  error NothingToWithdraw();
  error E3NotFailed();

  /// @notice A sale was requested. The supply is in this contract.
  /// @dev `gate` is zero when anyone may bid. A gate publishes its own configuration (the allowlist gate emits `AllowlistSet`).
  event SaleCreated(
    uint256 indexed e3Id,
    address indexed creator,
    uint8 revealMode,
    uint8 levels,
    uint256[LEVELS] prices,
    address saleToken,
    address paymentToken,
    uint256 supply,
    uint256 escrow,
    string title,
    address gate
  );
  /// @notice A bidder escrowed and got an index.
  event Deposited(uint256 indexed e3Id, address indexed bidder, uint256 index);
  /// @notice A bidder submitted a bid, or an update of it. The ciphertext is published here once.
  /// Its leaf is the next leaf of the input tree, in event order. `index` is the bidder index.
  event BidSubmitted(
    uint256 indexed e3Id,
    address indexed bidder,
    uint32 version,
    uint256 index,
    bytes ciphertext,
    bytes32 ctCommitment,
    bytes32 bidCommitment
  );
  /// @notice The sale was cleared from the published plaintext. `kind`: 0 undersubscribed, 1 capped, 2 uncapped.
  event SaleCleared(uint256 indexed e3Id, uint256 pStar, uint8 kind, uint8 step, uint256[LEVELS] c);
  event Claimed(uint256 indexed e3Id, address indexed bidder, uint256 tokens, uint256 paid, uint256 refund);
  /// @notice The claim window of a cleared sale: bidders can claim until `deadline`.
  event ClaimWindowOpened(uint256 indexed e3Id, uint256 deadline);
  /// @notice The creator swept the sale after the claim window: what was left of both tokens.
  event Swept(uint256 indexed e3Id, address indexed creator, uint256 saleTokens, uint256 paymentTokens);
  event ProceedsWithdrawn(uint256 indexed e3Id, address indexed creator, uint256 amount);
  event UnsoldWithdrawn(uint256 indexed e3Id, address indexed creator, uint256 amount);
  /// @notice The E3 failed: a bidder got the escrow back.
  event EscrowRefunded(uint256 indexed e3Id, address indexed bidder, uint256 amount);
  /// @notice The E3 failed: the creator got the supply back.
  event SupplyRefunded(uint256 indexed e3Id, address indexed creator, uint256 amount);

  /// @param _interfold The Interfold contract address
  /// @param _verifier The OpenVM receipt verifier address
  /// @param _imageId The receipt identity: `imageId()` of the OpenVM receipt verifier.
  /// @param _bidVerifier The generated verifier of `sealed_cca_bid`
  /// @param _claimVerifier The generated verifier of `sealed_cca_claim`
  /// @param _vkAnchor The anchor of `sealed_cca_bid` (`circuits/target/vk_anchor.json`)
  /// @param _dataAvailabilityVerifier The verifier of the output's availability receipt
  constructor(
    IInterfold _interfold,
    IOpenVmReceiptVerifier _verifier,
    bytes32 _imageId,
    IBidVerifier _bidVerifier,
    IBidVerifier _claimVerifier,
    bytes32 _vkAnchor,
    IDataAvailabilityVerifier _dataAvailabilityVerifier
  ) Ownable(msg.sender) EIP712("SealedCcaProgram", "1") {
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
  /// @dev `customParams` is `abi.encode(uint8 revealMode, uint8 levels, uint256[16] prices, address saleToken,
  /// uint256 supply, address paymentToken, uint256 escrow, string title, address gate, bytes gateConfig)`.
  /// `prices[levels..16]` must be zero. Interfold calls this inside `request`, and the requester is already
  /// set. The requester must have approved `supply` of the sale token to this contract before the request:
  /// this function pulls it. With `gate == address(0)` anyone may bid and `gateConfig` must be empty.
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
    inputs[e3Id]._init(TREE_DEPTH);
    inputs[e3Id]._insert(configLeaf(sale[e3Id].revealMode));
    Sale storage s = sale[e3Id];
    IERC20(s.saleToken).safeTransferFrom(s.creator, address(this), s.supply);
    if (s.gate != address(0)) IBidderGate(s.gate).configure(e3Id, gateConfig);
    return ENCRYPTION_SCHEME_ID;
  }

  /// @dev Decodes, checks and stores the sale of `e3Id`.
  function _initSale(uint256 e3Id, bytes calldata customParams) private returns (bytes memory gateConfig) {
    Sale memory s;
    (s, gateConfig) = SaleConfig.decode(customParams);
    s.creator = interfold.getE3(e3Id).requester;
    sale[e3Id] = s;
    _emitSaleCreated(e3Id);
  }

  function _emitSaleCreated(uint256 e3Id) private {
    Sale storage s = sale[e3Id];
    emit SaleCreated(e3Id, s.creator, s.revealMode, s.levels, s.prices, s.saleToken, s.paymentToken, s.supply, s.escrow, s.title, s.gate);
  }

  /// @notice The price of each step of the sale of `e3Id`.
  function salePrices(uint256 e3Id) external view returns (uint256[LEVELS] memory) {
    return sale[e3Id].prices;
  }

  // ---------------------------------------------------------------------------------------------
  // Deposit
  // ---------------------------------------------------------------------------------------------

  /// @notice Escrow the fixed amount and get a bidder index. The sender is the bidder. The bidder must
  /// have approved `sale.escrow` of the payment token to this contract.
  /// @param gateProof The proof of eligibility for the sale's gate, or empty.
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

  function _sale(uint256 e3Id) private view returns (Sale storage s) {
    s = sale[e3Id];
    if (s.creator == address(0)) revert E3DoesNotExist();
  }

  function _deposit(uint256 e3Id, address bidder, bytes calldata gateProof) private {
    Sale storage s = _sale(e3Id);
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

  /// @notice Whether `bidder` has deposited in the sale.
  function deposited(uint256 e3Id, address bidder) public view returns (bool) {
    return _indexPlusOne[e3Id][bidder] != 0;
  }

  /// @notice The index of a depositor, 0 to 111. It is 0 for an address that has not deposited: check `deposited`.
  function bidderIndex(uint256 e3Id, address bidder) public view returns (uint256) {
    uint256 indexPlusOne = _indexPlusOne[e3Id][bidder];
    return indexPlusOne == 0 ? 0 : indexPlusOne - 1;
  }

  // ---------------------------------------------------------------------------------------------
  // Bids
  // ---------------------------------------------------------------------------------------------

  /// @notice Leaf 0 of a sale: the configuration input, hashed into the field. The program reads the
  /// reveal mode from it, so the compute proof binds the mode through the input root.
  function configLeaf(uint8 revealMode) public pure returns (uint256) {
    return uint256(keccak256(abi.encodePacked(CONFIG_DOMAIN, revealMode))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The leaf of the ciphertext of a bid. The program computes the same value from the
  /// published bytes and the 25 bytes of metadata `bidder || uint40 version`.
  /// @param ciphertextHash `keccak256` of the ciphertext bytes.
  /// @param commitment The SAFE commitment of the ciphertext, which the bid proof binds.
  function inputLeaf(bytes32 ciphertextHash, bytes32 commitment, address bidder, uint32 version) public pure returns (uint256) {
    return uint256(sha256(abi.encodePacked(ciphertextHash, commitment, bidder, uint40(version)))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The EIP-712 digest that a bidder signs to let a relayer send a bid.
  /// @param version The version the bid will get: `bidCount + 1`.
  /// @param inputsHash `keccak256(abi.encode(ctCommitment, bidCommitment, keccak256(ciphertext)))`.
  function bidDigest(uint256 e3Id, address bidder, uint32 version, bytes32 inputsHash) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(BID_TYPEHASH, e3Id, bidder, version, inputsHash)));
  }

  /// @notice Submit a bid, or an update of the bidder's earlier bid. The bidder must have deposited.
  /// @param data `abi.encode(address bidder, bytes ciphertext, bytes32 ctCommitment, bytes32 bidCommitment,
  /// bytes proof, bytes gateProof, bytes signature)`. With an empty `signature` the sender must be `bidder`.
  /// Otherwise `signature` is the bidder's EIP-712 signature (`bidDigest`), and anyone may send.
  function publishInput(uint256 e3Id, bytes memory data) external override {
    E3 memory e3 = interfold.getE3(e3Id);
    if (block.timestamp > e3.inputWindow[1]) revert InputDeadlineReached();
    BidInput memory bid;
    (bid.bidder, bid.ciphertext, bid.ctCommitment, bid.bidCommitment, bid.proof, bid.gateProof, bid.signature) = abi.decode(
      data,
      (address, bytes, bytes32, bytes32, bytes, bytes, bytes)
    );
    Sale storage s = _sale(e3Id);
    if (bid.bidder == address(0)) revert BidderIsZero();
    if (bid.ciphertext.length == 0) revert EmptyInputData();
    uint256 indexPlusOne = _indexPlusOne[e3Id][bid.bidder];
    if (indexPlusOne == 0) revert NotDeposited(bid.bidder);
    uint32 version = bidCount[e3Id][bid.bidder] + 1;
    if (version > MAX_BIDS_PER_BIDDER) revert TooManyBids(bid.bidder);
    bytes32 ciphertextHash = keccak256(bid.ciphertext);

    _checkSender(e3Id, bid, version, ciphertextHash);
    if (s.gate != address(0) && !IBidderGate(s.gate).isEligible(e3Id, bid.bidder, bid.gateProof)) revert BidderNotEligible(bid.bidder);
    _verifyBidProof(e3Id, bid, s.levels, indexPlusOne - 1, version, e3.committeePublicKey);

    bidCount[e3Id][bid.bidder] = version;
    bidCommitments[e3Id][bid.bidder][version] = bid.bidCommitment;
    inputs[e3Id]._insert(inputLeaf(ciphertextHash, bid.ctCommitment, bid.bidder, version));
    emit BidSubmitted(e3Id, bid.bidder, version, indexPlusOne - 1, bid.ciphertext, bid.ctCommitment, bid.bidCommitment);
  }

  /// @dev A direct bid comes from its bidder. A relayed bid carries the bidder's signature over the
  /// version and the hash of the exact commitments and ciphertext, so a relayer cannot swap bytes
  /// and an old signature is useless once the bidder has bid again.
  function _checkSender(uint256 e3Id, BidInput memory bid, uint32 version, bytes32 ciphertextHash) private view {
    if (bid.signature.length == 0) {
      if (bid.bidder != msg.sender) revert SenderNotBidder(msg.sender, bid.bidder);
      return;
    }
    bytes32 inputsHash = keccak256(abi.encode(bid.ctCommitment, bid.bidCommitment, ciphertextHash));
    if (!SignatureChecker.isValidSignatureNow(bid.bidder, bidDigest(e3Id, bid.bidder, version, inputsHash), bid.signature)) {
      revert InvalidSignature(bid.bidder);
    }
  }

  /// @dev Public inputs of `sealed_cca_bid`: `ct_commitment, bid_commitment, bidder, e3_id, levels,
  /// bidder_index, version, pk_commitment, vk_anchor`. See `circuits/PUBLIC_INPUTS.md`. `e3_id` is
  /// `e3Id mod r`: an E3 id is 256 bits and can be above the BN254 scalar field.
  function _verifyBidProof(
    uint256 e3Id,
    BidInput memory bid,
    uint8 levels,
    uint256 index,
    uint32 version,
    bytes32 committeePublicKey
  ) private view {
    bytes32[] memory publicInputs = new bytes32[](9);
    publicInputs[0] = bid.ctCommitment;
    publicInputs[1] = bid.bidCommitment;
    publicInputs[2] = bytes32(uint256(uint160(bid.bidder)));
    publicInputs[3] = bytes32(e3Id % SNARK_SCALAR_FIELD);
    publicInputs[4] = bytes32(uint256(levels));
    publicInputs[5] = bytes32(index);
    publicInputs[6] = bytes32(uint256(version));
    publicInputs[7] = committeePublicKey;
    publicInputs[8] = vkAnchor;
    if (!bidVerifier.verify(bid.proof, publicInputs)) revert InvalidBidProof();
  }

  // ---------------------------------------------------------------------------------------------
  // Clearing
  // ---------------------------------------------------------------------------------------------

  /// @notice Clear the sale from the published plaintext. Anyone may call it once. `claim`,
  /// `withdrawUnsold` and `previewClaim` need it: `claim` and `withdrawUnsold` call it if nobody did.
  function clear(uint256 e3Id) public {
    if (_cleared[e3Id].cleared) return;
    Sale storage s = _sale(e3Id);
    bytes memory plaintext = interfold.getE3(e3Id).plaintextOutput;
    if (plaintext.length == 0) revert OutputNotPublished();
    uint256[LEVELS] memory c;
    (c, _countedPacked[e3Id]) = SaleOutput.decode(plaintext, s.levels, bidderCount[e3Id], bidderAt[e3Id], bidCount[e3Id]);

    SaleClearing.Result memory r = SaleClearing.clear(s.prices, s.levels, c, s.supply, s.escrow, s.saleUnit);
    Cleared storage out = _cleared[e3Id];
    out.cleared = true;
    out.kind = r.kind;
    out.step = r.step;
    out.pStar = r.pStar;
    out.fullTokens = r.fullTokens;
    out.marginalTokens = r.marginalTokens;
    out.sold = r.sold;
    out.claimDeadline = uint64(block.timestamp) + CLAIM_WINDOW;
    emit SaleCleared(e3Id, r.pStar, r.kind, r.step, c);
    emit ClaimWindowOpened(e3Id, out.claimDeadline);
  }

  /// @notice The clearing of the sale, after `clear`. The demand curve is in the `SaleCleared` event.
  /// @return cleared Whether `clear` ran.
  /// @return kind 0 undersubscribed, 1 capped, 2 uncapped.
  /// @return step The step `k` of the claim proof.
  /// @return pStar The uniform price per whole sale token, in payment-token base units.
  /// @return fullTokens The sale-token base units of a bidder filled in full.
  /// @return marginalTokens The sale-token base units of a marginal bidder.
  /// @return soldTotal The sale-token base units sold in total.
  /// @return claimDeadline The last second at which a bidder can claim; the creator can sweep after it.
  function clearing(
    uint256 e3Id
  )
    external
    view
    returns (
      bool cleared,
      uint8 kind,
      uint8 step,
      uint256 pStar,
      uint256 fullTokens,
      uint256 marginalTokens,
      uint256 soldTotal,
      uint256 claimDeadline
    )
  {
    Cleared storage out = _cleared[e3Id];
    return (out.cleared, out.kind, out.step, out.pStar, out.fullTokens, out.marginalTokens, out.sold, out.claimDeadline);
  }

  /// @notice Whether the creator swept the sale.
  function swept(uint256 e3Id) external view returns (bool) {
    return _cleared[e3Id].swept;
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

  /// @notice What a claim of `bidder` pays out when the claim proof shows the comparison `cmp` of the bid
  /// step and the clearing step (0: `b < k`, 1: `b == k`, 2: `b > k`). A bidder that was not counted
  /// gets the whole escrow back for any `cmp`. Needs `clear`.
  function previewClaim(uint256 e3Id, address bidder, uint8 cmp) public view returns (uint256 tokens, uint256 paid, uint256 refund) {
    if (!deposited(e3Id, bidder)) revert NotDeposited(bidder);
    if (cmp > 2) revert InvalidComparison(cmp);
    Cleared storage out = _cleared[e3Id];
    Sale storage s = sale[e3Id];
    if (countedVersion(e3Id, bidder) != 0) {
      SaleClearing.Result memory r = SaleClearing.Result(out.kind, out.step, out.pStar, out.fullTokens, out.marginalTokens, out.sold);
      tokens = SaleClearing.tokensFor(r, cmp);
      paid = SaleClearing.cost(tokens, out.pStar, s.saleUnit);
    }
    refund = s.escrow - paid;
  }

  /// @notice Pay a depositor the tokens and the refund of the clearing. Anyone may send it; the funds go to `bidder`.
  /// @param data `abi.encode(uint8 cmp, bytes proof)`: the claim proof and its output. It is empty (and
  /// ignored) when no proof is needed: the bidder was not counted, or the sale was undersubscribed.
  function claim(uint256 e3Id, address bidder, bytes calldata data) external {
    clear(e3Id);
    if (!deposited(e3Id, bidder)) revert NotDeposited(bidder);
    if (claimed[e3Id][bidder]) revert AlreadyClaimed(bidder);
    Cleared storage out = _cleared[e3Id];
    if (block.timestamp > out.claimDeadline) revert ClaimWindowClosed(out.claimDeadline);
    uint8 version = countedVersion(e3Id, bidder);
    uint8 cmp = 2;
    if (version != 0 && out.kind != SaleClearing.KIND_UNDERSUBSCRIBED) {
      bytes memory proof;
      (cmp, proof) = abi.decode(data, (uint8, bytes));
      if (cmp > 2) revert InvalidComparison(cmp);
      _verifyClaimProof(e3Id, bidder, bidCommitments[e3Id][bidder][version], out.step, cmp, proof);
    }
    (uint256 tokens, uint256 paid, uint256 refund) = previewClaim(e3Id, bidder, cmp);
    claimed[e3Id][bidder] = true;
    out.claimedCount++;
    out.tokensClaimed += tokens;
    proceedsAvailable[e3Id] += paid;
    Sale storage s = sale[e3Id];
    if (tokens != 0) IERC20(s.saleToken).safeTransfer(bidder, tokens);
    if (refund != 0) IERC20(s.paymentToken).safeTransfer(bidder, refund);
    emit Claimed(e3Id, bidder, tokens, paid, refund);
  }

  /// @dev Public inputs of `sealed_cca_claim`: `bid_commitment, bidder, e3_id, k, cmp`. `e3_id` is `e3Id mod r`.
  function _verifyClaimProof(uint256 e3Id, address bidder, bytes32 bidCommitment, uint8 step, uint8 cmp, bytes memory proof) private view {
    bytes32[] memory publicInputs = new bytes32[](5);
    publicInputs[0] = bidCommitment;
    publicInputs[1] = bytes32(uint256(uint160(bidder)));
    publicInputs[2] = bytes32(e3Id % SNARK_SCALAR_FIELD);
    publicInputs[3] = bytes32(uint256(step));
    publicInputs[4] = bytes32(uint256(cmp));
    if (!claimVerifier.verify(proof, publicInputs)) revert InvalidClaimProof();
  }

  // ---------------------------------------------------------------------------------------------
  // Creator
  // ---------------------------------------------------------------------------------------------

  /// @notice The creator takes the payments of the claims so far. The payments of the bidders that
  /// did not claim yet are still in the contract.
  function withdrawProceeds(uint256 e3Id) external {
    Sale storage s = sale[e3Id];
    if (msg.sender != s.creator) revert NotCreator(msg.sender);
    uint256 amount = proceedsAvailable[e3Id];
    if (amount == 0) revert NothingToWithdraw();
    proceedsAvailable[e3Id] = 0;
    IERC20(s.paymentToken).safeTransfer(s.creator, amount);
    emit ProceedsWithdrawn(e3Id, s.creator, amount);
  }

  /// @notice The sale tokens that the clearing does not sell: `supply - sold`. Needs `clear`.
  function unsoldAmount(uint256 e3Id) public view returns (uint256) {
    Cleared storage out = _cleared[e3Id];
    if (!out.cleared) revert NotCleared();
    return sale[e3Id].supply - out.sold;
  }

  /// @notice The creator takes the sale tokens that the clearing does not sell. Once. The tokens
  /// of the winners that did not claim yet stay in the contract.
  function withdrawUnsold(uint256 e3Id) external {
    Sale storage s = sale[e3Id];
    if (msg.sender != s.creator) revert NotCreator(msg.sender);
    clear(e3Id);
    if (unsoldWithdrawn[e3Id]) revert NothingToWithdraw();
    uint256 amount = unsoldAmount(e3Id);
    if (amount == 0) revert NothingToWithdraw();
    unsoldWithdrawn[e3Id] = true;
    IERC20(s.saleToken).safeTransfer(s.creator, amount);
    emit UnsoldWithdrawn(e3Id, s.creator, amount);
  }

  /// @notice After the claim window, the creator takes everything that is still held for the sale: the
  /// sale tokens of winners that did not claim, the unsold sale tokens that the creator did not take yet,
  /// the escrows of bidders that did not claim, and the payments that the creator did not take yet. Once.
  /// It moves only the amounts of this sale, which the contract counts per sale.
  function sweep(uint256 e3Id) external {
    Sale storage s = sale[e3Id];
    if (msg.sender != s.creator) revert NotCreator(msg.sender);
    Cleared storage out = _cleared[e3Id];
    if (!out.cleared) revert NotCleared();
    if (block.timestamp <= out.claimDeadline) revert ClaimWindowOpen(out.claimDeadline);
    if (out.swept) revert AlreadySwept();
    out.swept = true;
    // Sale tokens: the supply minus what claimants got and what the creator already took as unsold.
    uint256 saleTokens = s.supply - out.tokensClaimed - (unsoldWithdrawn[e3Id] ? s.supply - out.sold : 0);
    // Payment tokens: one escrow for each depositor that did not claim, and the payments not yet withdrawn.
    uint256 paymentTokens = (bidderCount[e3Id] - out.claimedCount) * s.escrow + proceedsAvailable[e3Id];
    unsoldWithdrawn[e3Id] = true;
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
    if (!deposited(e3Id, bidder)) revert NotDeposited(bidder);
    if (claimed[e3Id][bidder]) revert AlreadyClaimed(bidder);
    claimed[e3Id][bidder] = true;
    Sale storage s = sale[e3Id];
    IERC20(s.paymentToken).safeTransfer(bidder, s.escrow);
    emit EscrowRefunded(e3Id, bidder, s.escrow);
  }

  /// @notice The E3 failed, so there is no output: the creator takes the supply back.
  function refundSupply(uint256 e3Id) external {
    _requireFailed(e3Id);
    Sale storage s = sale[e3Id];
    if (msg.sender != s.creator) revert NotCreator(msg.sender);
    if (supplyRefunded[e3Id]) revert NothingToWithdraw();
    supplyRefunded[e3Id] = true;
    IERC20(s.saleToken).safeTransfer(s.creator, s.supply);
    emit SupplyRefunded(e3Id, s.creator, s.supply);
  }

  function _requireFailed(uint256 e3Id) private view {
    _sale(e3Id);
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
