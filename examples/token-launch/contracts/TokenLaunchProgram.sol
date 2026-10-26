// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IOpenVmReceiptVerifier } from "@interfold/contracts/contracts/interfaces/IOpenVmReceiptVerifier.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { OpenVmComputeProof } from "@interfold/contracts/contracts/lib/OpenVmComputeProof.sol";
import { IDataAvailabilityVerifier, IE3ProgramDataAvailability } from "@interfold/contracts/contracts/interfaces/IDataAvailabilityVerifier.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { LazyIMTData } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { IBidVerifier } from "./interfaces/IBidVerifier.sol";
import { ITokenLaunch } from "./interfaces/ITokenLaunch.sol";
import { IncrementalTree } from "./libraries/IncrementalTree.sol";
import { E3Info, E3Reader } from "./libraries/E3Reader.sol";
import { BidContext, ClaimContext, ProofInputs } from "./libraries/ProofInputs.sol";
import { Grid, ProbeSearch } from "./libraries/ProbeSearch.sol";
import { SaleClearing } from "./libraries/SaleClearing.sol";
import { SaleConfig, Sale } from "./libraries/SaleConfig.sol";
import { SaleOutput } from "./libraries/SaleOutput.sol";
import { Marginal, Progress, SaleState } from "./libraries/SaleState.sol";
import { Settlement } from "./libraries/Settlement.sol";

/// @title Sealed-bid, one-batch, uniform-price token launch with private budgets and private max prices.
/// @notice A creator sells `supply` of a sale token for a payment token on a grid of `levels` prices. A bidder
/// picks an escrow tier `X`, and bids a private budget `B <= X` and a private max price step `b`. The FHE program
/// only adds. The committee never decrypts the demand curve: a probe search over two E3 rounds reveals the
/// budget sums `F[l]` at a few levels (`ProbeSearch`), and `SaleClearing` clears the sale on them. A claim then
/// proves in zero knowledge that a bid is in the claim tree and how it compares with the clearing step, and the
/// tokens and the refund go to a fresh address: the claim does not name the bidder or the bid.
///
/// A sale is two E3s of one requester with the same input window and committee size. The first (round 1) has the
/// id of the sale, the second (round 2) is linked to it. This contract is the program of both. A bid is one
/// `publishInput` call on the sale: it stores one ciphertext in the input tree of each E3 and the bid commitment in
/// the claim tree, with one proof for the pair. Input 0 of each E3 is its configuration (role, levels, probe
/// mask). Round 2 starts with a pending configuration, which `publishProbes` replaces after round 1 decrypts.
///
/// Flow: the creator approves the sale token, requests round 1 (`validate` pulls the supply) and requests
/// round 2. Bidders send bids until the input window ends. After round 1 decrypts, anyone calls `publishProbes`.
/// After round 2 decrypts, anyone calls `clear`. Bidders claim until the claim deadline; the creator then sweeps.
/// In a capped sale the bids at the clearing step share the last tokens first bid first: their claims register in a
/// 3-day window and `payMarginal` pays them after it (see `Settlement`).
/// If an E3 fails, or a decrypted output cannot be valid, the bidders and the creator take their funds back.
contract TokenLaunchProgram is ITokenLaunch, IE3Program, IE3ProgramDataAvailability, IERC165, Ownable, EIP712 {
  using IncrementalTree for LazyIMTData;
  using SafeERC20 for IERC20;

  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  /// @notice The prefix of the configuration input. The program uses the same bytes.
  bytes public constant CONFIG_DOMAIN = "interfold-token-launch-config-v1";
  uint8 private constant ROLE_SALE = 1;
  uint8 private constant ROLE_ROUND_TWO = 2;
  uint8 public constant TREE_DEPTH = 20;
  uint8 public constant CLAIM_TREE_DEPTH = 7;
  /// @notice The most bids of a sale: `n * 3 <= 256`, so a budget digit sum fits the plaintext modulus 257.
  uint256 public constant MAX_BIDDERS = 85;
  /// @notice How long a bidder at the clearing step of a capped sale can register a marginal claim after `clear`.
  uint64 public constant MARGINAL_WINDOW = 3 days;
  /// @notice How long a bidder can claim after `clear`. After it, the creator can sweep what is left.
  uint64 public constant CLAIM_WINDOW = 30 days;
  /// @notice The EIP-712 type of a relayed bid.
  bytes32 public constant BID_TYPEHASH = keccak256("Bid(uint256 saleId,address bidder,uint8 tier,bytes32 inputsHash)");
  uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  /// @dev Leaf 0 of round 2 until `publishProbes`. No program accepts it as a role-2 configuration.
  uint256 private constant PENDING_LEAF = uint256(keccak256("interfold-token-launch-pending-v1")) % SNARK_SCALAR_FIELD;

  IInterfold public interfold;
  IOpenVmReceiptVerifier public verifier;
  bytes32 public imageId;
  /// @notice Verifies the pair bid proof (`token_launch_bid`).
  IBidVerifier public immutable bidVerifier;
  /// @notice Verifies the claim proof (`token_launch_claim`).
  IBidVerifier public immutable claimVerifier;
  /// @notice The VK chain of the circuits the bid proof passes through.
  bytes32 public immutable vkAnchor;
  /// @notice Verifies the availability receipt of the ciphertext output.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;

  mapping(address => bool) public authorizedContracts;
  mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
  /// @notice The input tree of each E3 (round 1 and round 2). Leaf 0 is the configuration, leaf `i + 1` is bid `i`.
  mapping(uint256 e3Id => LazyIMTData) public inputs;
  /// @dev 0 for an E3 that this program does not know, `ROLE_SALE` or `ROLE_ROUND_TWO`.
  mapping(uint256 e3Id => uint8) private _roles;
  /// @dev For a round-2 E3: the sale it belongs to.
  mapping(uint256 e3Id2 => uint256 saleId) private _saleOfRoundTwo;
  /// @dev Everything else of a sale, by the E3 id of round 1.
  mapping(uint256 saleId => SaleState) private _sales;

  /// @param _interfold The Interfold contract address
  /// @param _verifier The OpenVM receipt verifier address
  /// @param _imageId The receipt identity: `imageId()` of the OpenVM receipt verifier.
  /// @param _bidVerifier The generated verifier of `token_launch_bid`
  /// @param _claimVerifier The generated verifier of `token_launch_claim`
  /// @param _vkAnchor The anchor of `token_launch_bid` (`circuits/target/vk_anchor.json`)
  /// @param _dataAvailabilityVerifier The verifier of the output's availability receipt
  constructor(
    IInterfold _interfold,
    IOpenVmReceiptVerifier _verifier,
    bytes32 _imageId,
    IBidVerifier _bidVerifier,
    IBidVerifier _claimVerifier,
    bytes32 _vkAnchor,
    IDataAvailabilityVerifier _dataAvailabilityVerifier
  ) Ownable(msg.sender) EIP712("TokenLaunchProgram", "1") {
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
  /// @dev `customParams` is `abi.encode(uint8 role, bytes body)`. Interfold calls this inside `request`, and the
  /// requester is already set.
  /// - Role 1 (the sale, round 1): `body = abi.encode(uint8 levels, uint256[16] prices, address saleToken,
  ///   uint256 supply, address paymentToken, uint256 budgetUnit, uint16[4] tiers, string title)`. The requester must
  ///   have approved `supply` of the sale token to this contract before the request: this function pulls it.
  /// - Role 2 (round 2): `body = abi.encode(uint256 saleId)`. The sale needs no round 2 yet, and the two E3s need
  ///   the same requester, input window and committee size.
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
    (uint8 role, bytes memory body) = abi.decode(customParams, (uint8, bytes));
    if (role == ROLE_SALE) _createSale(e3Id, body);
    else if (role == ROLE_ROUND_TWO) _linkRoundTwo(e3Id, abi.decode(body, (uint256)));
    else revert InvalidRole(role);
    return ENCRYPTION_SCHEME_ID;
  }

  function _createSale(uint256 saleId, bytes memory body) private {
    SaleState storage st = _sales[saleId];
    SaleConfig.create(st.sale, saleId, E3Reader.read(address(interfold), saleId).requester, body);
    _roles[saleId] = ROLE_SALE;
    st.claimTree.init(CLAIM_TREE_DEPTH);
    inputs[saleId].init(TREE_DEPTH);
    inputs[saleId].insert(configLeaf(ROLE_SALE, st.sale.levels, ProbeSearch.coarseProbeMask(st.sale.levels)));
    IERC20(st.sale.saleToken).safeTransferFrom(st.sale.creator, address(this), st.sale.supply);
  }

  function _linkRoundTwo(uint256 e3Id, uint256 saleId) private {
    SaleState storage st = _sales[saleId];
    if (_roles[saleId] != ROLE_SALE) revert InvalidRoundTwo();
    if (st.roundTwo != 0) revert RoundTwoAlreadyLinked(saleId);
    E3Info memory one = E3Reader.read(address(interfold), saleId);
    E3Info memory two = E3Reader.read(address(interfold), e3Id);
    if (
      two.requester != st.sale.creator ||
      two.windowStart != one.windowStart ||
      two.windowEnd != one.windowEnd ||
      two.committeeSize != one.committeeSize
    ) revert RoundTwoMismatch();
    _roles[e3Id] = ROLE_ROUND_TWO;
    st.roundTwo = e3Id;
    _saleOfRoundTwo[e3Id] = saleId;
    inputs[e3Id].init(TREE_DEPTH);
    inputs[e3Id].insert(PENDING_LEAF);
    emit RoundTwoLinked(saleId, e3Id);
  }

  // ---------------------------------------------------------------------------------------------
  // Hashes
  // ---------------------------------------------------------------------------------------------

  /// @inheritdoc ITokenLaunch
  function configBytes(uint8 role, uint8 levels, uint16 probeMask) public pure returns (bytes memory) {
    return abi.encodePacked(CONFIG_DOMAIN, role, levels, probeMask);
  }

  /// @inheritdoc ITokenLaunch
  function configLeaf(uint8 role, uint8 levels, uint16 probeMask) public pure returns (uint256) {
    return uint256(keccak256(configBytes(role, levels, probeMask))) % SNARK_SCALAR_FIELD;
  }

  /// @inheritdoc ITokenLaunch
  function leafOf(bytes32 ciphertextHash, bytes32 ctCommitment, address bidder, uint256 index) public pure returns (uint256) {
    return uint256(sha256(abi.encodePacked(ciphertextHash, ctCommitment, bidder, uint40(index)))) % SNARK_SCALAR_FIELD;
  }

  /// @inheritdoc ITokenLaunch
  function bidDigest(uint256 saleId, address bidder, uint8 tier, bytes32 inputsHash) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(BID_TYPEHASH, saleId, bidder, tier, inputsHash)));
  }

  // ---------------------------------------------------------------------------------------------
  // Bids
  // ---------------------------------------------------------------------------------------------

  /// @notice Submit a bid to the sale `saleId`: `data = abi.encode(BidInput)`. With an empty `signature` the sender
  /// must be `bidder`. Otherwise `signature` is the bidder's EIP-712 signature (`bidDigest`), anyone may send it,
  /// and the permit fields are tried first. The call takes the escrow of the tier from `bidder`, verifies the proof,
  /// and inserts the ciphertext leaf in both input trees and the commitment in the claim tree.
  function publishInput(uint256 saleId, bytes memory data) external override {
    if (_roles[saleId] != ROLE_SALE) revert NotASale(saleId);
    SaleState storage st = _sales[saleId];
    uint256 e3Id2 = st.roundTwo;
    if (e3Id2 == 0) revert RoundTwoNotLinked();
    E3Info memory one = E3Reader.read(address(interfold), saleId);
    if (block.timestamp > one.windowEnd) revert InputDeadlineReached();
    bytes32 key2 = E3Reader.read(address(interfold), e3Id2).key;
    if (one.key == bytes32(0) || key2 == bytes32(0)) revert KeyNotPublished();
    BidInput memory bid = abi.decode(data, (BidInput));
    if (bid.bidder == address(0)) revert BidderIsZero();
    if (bid.ciphertext1.length == 0 || bid.ciphertext2.length == 0) revert EmptyInputData();
    uint256 index = st.progress.bidCount;
    if (index >= MAX_BIDDERS) revert TooManyBidders();
    if (st.hasBid[bid.bidder]) revert AlreadyBid(bid.bidder);
    if (uint256(bid.bidCommitment) >= SNARK_SCALAR_FIELD) revert InvalidBidCommitment();
    if (bid.tier >= st.sale.tiers.length || st.sale.tiers[bid.tier] == 0) revert InvalidTier(bid.tier);

    _checkSender(saleId, bid);
    ProofInputs.verifyBid(
      address(bidVerifier),
      bid,
      BidContext(saleId, index, st.sale.levels, st.sale.tiers[bid.tier], one.key, key2, vkAnchor)
    );

    st.progress.bidCount = uint32(index + 1);
    st.hasBid[bid.bidder] = true;
    st.bids[index].bidder = bid.bidder;
    st.bids[index].tier = bid.tier;
    inputs[saleId].insert(leafOf(keccak256(bid.ciphertext1), bid.ctCommitment1, bid.bidder, index));
    inputs[e3Id2].insert(leafOf(keccak256(bid.ciphertext2), bid.ctCommitment2, bid.bidder, index));
    st.claimTree.insert(uint256(bid.bidCommitment));

    uint256 escrow = uint256(st.sale.tiers[bid.tier]) * st.sale.budgetUnit;
    st.accounts.escrowTotal += escrow;
    if (bid.signature.length != 0) {
      // A permit that someone else already used does not fail the bid, if the allowance is enough.
      try IERC20Permit(st.sale.paymentToken).permit(bid.bidder, address(this), escrow, bid.permitDeadline, bid.v, bid.r, bid.s) {} catch {}
    }
    IERC20(st.sale.paymentToken).safeTransferFrom(bid.bidder, address(this), escrow);
    emit BidSubmitted(
      saleId,
      bid.bidder,
      index,
      bid.tier,
      bid.ciphertext1,
      bid.ciphertext2,
      bid.ctCommitment1,
      bid.ctCommitment2,
      bid.bidCommitment
    );
  }

  /// @dev A direct bid comes from its bidder. A relayed bid carries the bidder's signature over the tier and the
  /// hash of the exact commitments and ciphertexts, so a relayer cannot swap bytes. The signature has no nonce:
  /// an address bids once per sale, and the digest names the sale.
  function _checkSender(uint256 saleId, BidInput memory bid) private view {
    if (bid.signature.length == 0) {
      if (bid.bidder != msg.sender) revert SenderNotBidder(msg.sender, bid.bidder);
      return;
    }
    bytes32 inputsHash = keccak256(
      abi.encode(bid.ctCommitment1, bid.ctCommitment2, bid.bidCommitment, keccak256(bid.ciphertext1), keccak256(bid.ciphertext2))
    );
    if (!SignatureChecker.isValidSignatureNow(bid.bidder, bidDigest(saleId, bid.bidder, bid.tier, inputsHash), bid.signature)) {
      revert InvalidSignature(bid.bidder);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Rounds
  // ---------------------------------------------------------------------------------------------

  /// @inheritdoc ITokenLaunch
  function publishProbes(uint256 saleId) external {
    SaleState storage st = _sales[saleId];
    Progress storage p = st.progress;
    if (_roles[saleId] != ROLE_SALE || p.probed || p.cleared || p.abortReason != AbortReason.None) revert WrongPhase(phase(saleId));
    E3Info memory one = E3Reader.read(address(interfold), saleId);
    if (one.plaintext.length == 0) revert OutputNotPublished();
    if (st.roundTwo == 0) return _abort(saleId, AbortReason.NoRoundTwo);
    uint16 mask1 = ProbeSearch.coarseProbeMask(st.sale.levels);
    (bool ok, uint256[16] memory sums, uint256 counted) = SaleOutput.decode(one.plaintext, mask1, p.bidCount);
    if (ok && _storeProbes(saleId, mask1, sums, counted)) return;
    _abort(saleId, AbortReason.InvalidRound1Output);
  }

  /// @dev Runs round 1 of the probe search on the decoded sums; on success stores it and fixes the input 0 of round 2.
  function _storeProbes(uint256 saleId, uint16 mask1, uint256[16] memory sums, uint256 counted) private returns (bool) {
    SaleState storage st = _sales[saleId];
    (bool valid, uint8 lo, uint8 hi, uint16 mask2) = ProbeSearch.round1(_grid(st), sums, mask1);
    if (!valid) return false;
    Progress storage p = st.progress;
    p.probed = true;
    p.lo = lo;
    p.hi = hi;
    p.probeMask2 = mask2;
    st.counted1 = counted;
    for (uint256 l = 0; l < st.sale.levels; l++) {
      if (sums[l] != 0) st.sums1[l] = uint32(sums[l]);
    }
    inputs[st.roundTwo].update(configLeaf(ROLE_ROUND_TWO, st.sale.levels, mask2), 0);
    emit ProbesPublished(saleId, st.roundTwo, lo, hi, mask2, configBytes(ROLE_ROUND_TWO, st.sale.levels, mask2));
    return true;
  }

  /// @inheritdoc ITokenLaunch
  function clear(uint256 saleId) external {
    SaleState storage st = _sales[saleId];
    Progress storage p = st.progress;
    if (!p.probed || p.cleared || p.abortReason != AbortReason.None) revert WrongPhase(phase(saleId));
    bytes memory plaintext = E3Reader.read(address(interfold), st.roundTwo).plaintext;
    if (plaintext.length == 0) revert OutputNotPublished();
    uint256 bids = p.bidCount;

    (bool ok, uint256[16] memory sums2, uint256 counted) = SaleOutput.decode(plaintext, p.probeMask2, bids);
    if (!ok) return _abort(saleId, AbortReason.InvalidRound2Output);
    if (counted != st.counted1) return _abortOnMismatch(saleId, bids, counted ^ st.counted1);
    if (!_storeClearing(saleId, sums2, counted)) _abort(saleId, AbortReason.InvalidRound2Output);
  }

  /// @dev Runs round 2 of the probe search and the clearing; on success stores the clearing and opens the claims.
  function _storeClearing(uint256 saleId, uint256[16] memory sums2, uint256 counted) private returns (bool) {
    SaleState storage st = _sales[saleId];
    Grid memory g = _grid(st);
    (bool valid, uint8 lstar, uint256[16] memory sums) = ProbeSearch.round2(
      g,
      _readSums1(st),
      sums2,
      ProbeSearch.coarseProbeMask(st.sale.levels),
      st.progress.lo,
      st.progress.probeMask2
    );
    if (!valid) return false;
    _finishClearing(saleId, SaleClearing.clear(g, lstar, sums), counted, sums);
    return true;
  }

  function _finishClearing(uint256 saleId, SaleClearing.Result memory r, uint256 counted, uint256[16] memory sums) private {
    SaleState storage st = _sales[saleId];
    Progress storage p = st.progress;
    st.cleared.kind = r.kind;
    st.cleared.step = r.step;
    st.cleared.pStar = r.pStar;
    st.cleared.sold = r.sold;
    st.cleared.remaining = r.remaining;
    st.cleared.countedMask = counted;
    st.cleared.root = st.claimTree.rootAt(CLAIM_TREE_DEPTH);
    p.cleared = true;
    p.marginalDeadline = uint64(block.timestamp) + (r.kind == SaleClearing.KIND_CAPPED ? MARGINAL_WINDOW : 0);
    p.claimDeadline = uint64(block.timestamp) + CLAIM_WINDOW;
    uint256 dropped;
    for (uint256 i = 0; i < p.bidCount; i++) {
      if ((counted >> i) & 1 == 0) dropped += _escrowOf(st, i);
    }
    st.accounts.droppedEscrow = dropped;
    emit SaleCleared(saleId, r.kind, r.step, r.pStar, r.sold, counted, ProbeSearch.coarseProbeMask(st.sale.levels) | p.probeMask2, sums);
  }

  function _abort(uint256 saleId, AbortReason reason) private {
    _sales[saleId].progress.abortReason = reason;
    emit SaleAborted(saleId, reason);
  }

  /// @dev A bid that opens in one round but not the other is an attack on the sums: its escrow is forfeited.
  function _abortOnMismatch(uint256 saleId, uint256 bids, uint256 forfeited) private {
    SaleState storage st = _sales[saleId];
    uint256 amount;
    for (uint256 i = 0; i < bids; i++) {
      if ((forfeited >> i) & 1 != 0) amount += _escrowOf(st, i);
    }
    st.forfeitMask = forfeited;
    st.accounts.forfeitedEscrow = amount;
    _abort(saleId, AbortReason.CountedSetMismatch);
  }

  function _grid(SaleState storage st) private view returns (Grid memory g) {
    g.prices = st.sale.prices;
    g.levels = st.sale.levels;
    g.supply = st.sale.supply;
    g.budgetUnit = st.sale.budgetUnit;
    g.saleUnit = st.sale.saleUnit;
  }

  function _readSums1(SaleState storage st) private view returns (uint256[16] memory sums) {
    for (uint256 l = 0; l < 16; l++) sums[l] = st.sums1[l];
  }

  function _escrowOf(SaleState storage st, uint256 index) private view returns (uint256) {
    return uint256(st.sale.tiers[st.bids[index].tier]) * st.sale.budgetUnit;
  }

  // ---------------------------------------------------------------------------------------------
  // Claims, refunds and the creator: see `Settlement`
  // ---------------------------------------------------------------------------------------------

  /// @inheritdoc ITokenLaunch
  function claim(uint256 saleId, bytes calldata data) external {
    Settlement.claim(_sales[saleId], saleId, data, address(claimVerifier));
  }

  /// @inheritdoc ITokenLaunch
  function payMarginal(uint256 saleId, uint256 index) external {
    Settlement.payMarginal(_sales[saleId], saleId, index);
  }

  /// @inheritdoc ITokenLaunch
  function refundDropped(uint256 saleId, uint256 index) external {
    Settlement.refundDropped(_sales[saleId], saleId, index);
  }

  /// @inheritdoc ITokenLaunch
  function refundEscrow(uint256 saleId, uint256 index) external {
    _requireFailedOrAborted(saleId);
    Settlement.refundEscrow(_sales[saleId], saleId, index);
  }

  /// @inheritdoc ITokenLaunch
  function refundSupply(uint256 saleId) external {
    _requireFailedOrAborted(saleId);
    Settlement.refundSupply(_sales[saleId], saleId);
  }

  /// @inheritdoc ITokenLaunch
  function withdrawForfeited(uint256 saleId) external {
    Settlement.withdrawForfeited(_sales[saleId], saleId);
  }

  /// @inheritdoc ITokenLaunch
  function withdrawProceeds(uint256 saleId) external {
    Settlement.withdrawProceeds(_sales[saleId], saleId);
  }

  /// @inheritdoc ITokenLaunch
  function withdrawUnsold(uint256 saleId) external {
    Settlement.withdrawUnsold(_sales[saleId], saleId);
  }

  /// @inheritdoc ITokenLaunch
  function sweep(uint256 saleId) external {
    Settlement.sweep(_sales[saleId], saleId);
  }

  function _requireFailedOrAborted(uint256 saleId) private view {
    Phase current = phase(saleId);
    if (current != Phase.Failed && current != Phase.Aborted) revert WrongPhase(current);
  }

  // ---------------------------------------------------------------------------------------------
  // Views
  // ---------------------------------------------------------------------------------------------

  /// @inheritdoc ITokenLaunch
  function getSale(uint256 saleId) external view returns (SaleInfo memory info) {
    Sale storage s = _sales[saleId].sale;
    info = SaleInfo(s.creator, s.levels, s.saleToken, s.paymentToken, s.supply, s.budgetUnit, s.saleUnit, s.title);
  }

  /// @inheritdoc ITokenLaunch
  function roundTwo(uint256 saleId) external view returns (uint256) {
    return _sales[saleId].roundTwo;
  }

  /// @inheritdoc ITokenLaunch
  function salePrices(uint256 saleId) external view returns (uint256[16] memory) {
    return _sales[saleId].sale.prices;
  }

  /// @inheritdoc ITokenLaunch
  function saleTiers(uint256 saleId) external view returns (uint16[4] memory) {
    return _sales[saleId].sale.tiers;
  }

  /// @inheritdoc ITokenLaunch
  function bidCount(uint256 saleId) external view returns (uint256) {
    return _sales[saleId].progress.bidCount;
  }

  /// @inheritdoc ITokenLaunch
  function bidderAt(uint256 saleId, uint256 index) external view returns (address) {
    return _sales[saleId].bids[index].bidder;
  }

  /// @inheritdoc ITokenLaunch
  function bidInfo(uint256 saleId, uint256 index) external view returns (address bidder, uint8 tier, bytes32 commitment) {
    SaleState storage st = _sales[saleId];
    // The claim tree keeps its leaves: leaf `index` is the commitment.
    return (st.bids[index].bidder, st.bids[index].tier, bytes32(st.claimTree.leafAt(uint40(index))));
  }

  /// @inheritdoc ITokenLaunch
  function phase(uint256 saleId) public view returns (Phase) {
    if (_roles[saleId] != ROLE_SALE) return Phase.None;
    SaleState storage st = _sales[saleId];
    if (st.progress.abortReason != AbortReason.None) return Phase.Aborted;
    if (st.progress.cleared) return Phase.Cleared;
    uint256 e3Id2 = st.roundTwo;
    if (
      interfold.getE3Stage(saleId) == IInterfold.E3Stage.Failed || (e3Id2 != 0 && interfold.getE3Stage(e3Id2) == IInterfold.E3Stage.Failed)
    ) return Phase.Failed;
    if (st.progress.probed) return E3Reader.read(address(interfold), e3Id2).plaintext.length == 0 ? Phase.Round2 : Phase.Clearable;
    E3Info memory one = E3Reader.read(address(interfold), saleId);
    if (one.plaintext.length != 0) return Phase.Probing;
    return block.timestamp > one.windowEnd ? Phase.Round1 : Phase.Bidding;
  }

  /// @inheritdoc ITokenLaunch
  function probeInfo(
    uint256 saleId
  ) external view returns (uint8 lo, uint8 hi, uint16 probeMask1, uint16 probeMask2, uint256[16] memory sums1) {
    SaleState storage st = _sales[saleId];
    if (!st.progress.probed) return (0, 0, 0, 0, sums1);
    return (st.progress.lo, st.progress.hi, ProbeSearch.coarseProbeMask(st.sale.levels), st.progress.probeMask2, _readSums1(st));
  }

  /// @inheritdoc ITokenLaunch
  function clearing(uint256 saleId) external view returns (ClearingInfo memory info) {
    SaleState storage st = _sales[saleId];
    info = ClearingInfo(
      st.progress.cleared,
      st.cleared.kind,
      st.cleared.step,
      st.progress.marginalDeadline,
      st.progress.claimDeadline,
      st.cleared.pStar,
      st.cleared.sold,
      st.cleared.remaining,
      st.cleared.countedMask,
      st.cleared.root
    );
  }

  /// @inheritdoc ITokenLaunch
  function claimRoot(uint256 saleId) external view returns (uint256) {
    SaleState storage st = _sales[saleId];
    return st.progress.cleared ? st.cleared.root : st.claimTree.rootAt(CLAIM_TREE_DEPTH);
  }

  /// @inheritdoc ITokenLaunch
  function previewClaim(
    uint256 saleId,
    uint8 cmp,
    uint16 budgetUnits,
    uint16 escrowUnits
  ) external view returns (uint256, uint256, uint256) {
    return Settlement.previewClaim(_sales[saleId], cmp, budgetUnits, escrowUnits);
  }

  /// @inheritdoc ITokenLaunch
  function previewMarginal(uint256 saleId, uint256 index) external view returns (uint256, uint256, uint256) {
    return Settlement.marginalAmounts(_sales[saleId], index);
  }

  /// @inheritdoc ITokenLaunch
  function marginalInfo(
    uint256 saleId,
    uint256 index
  ) external view returns (bool registered, uint16 budgetUnits, address recipient, bool paid) {
    Marginal storage m = _sales[saleId].marginals[index];
    return (m.registered, m.budgetUnits, m.recipient, m.paid);
  }

  /// @inheritdoc ITokenLaunch
  function nullifierUsed(uint256 saleId, bytes32 nullifier) external view returns (bool) {
    return _sales[saleId].nullifiers[nullifier];
  }

  /// @inheritdoc ITokenLaunch
  function proceedsAvailable(uint256 saleId) external view returns (uint256) {
    return _sales[saleId].accounts.proceeds;
  }

  // ---------------------------------------------------------------------------------------------
  // Compute proof
  // ---------------------------------------------------------------------------------------------

  /// @notice Verify the compute proof of round 1 or round 2.
  /// @dev Round 2 must not compute before `publishProbes` replaced its pending configuration.
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
    if (_roles[e3Id] == ROLE_ROUND_TWO && !_sales[_saleOfRoundTwo[e3Id]].progress.probed) revert ProbesNotPublished();
    E3Info memory e3 = E3Reader.read(address(interfold), e3Id);
    bytes32 paramsHash = paramsHashes[e3Id];
    bytes32 inputRoot = bytes32(inputs[e3Id].root());
    OpenVmComputeProof.Proof memory computeProof = OpenVmComputeProof.decode(proof);
    if (computeProof.paramsHash != paramsHash || computeProof.inputRoot != inputRoot) revert InvalidComputeContext();
    bytes memory journal = OpenVmComputeProof.journal(
      bytes32(block.chainid),
      bytes32(uint256(uint160(address(interfold)))),
      bytes32(e3Id),
      e3.encryptionSchemeId,
      e3.key,
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
