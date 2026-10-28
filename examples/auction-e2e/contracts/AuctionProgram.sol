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
import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { IBidVerifier } from "./interfaces/IBidVerifier.sol";
import { IBidderGate } from "./interfaces/IBidderGate.sol";

/// @title Sealed-bid auction: first-price or second-price (Vickrey) with regions, second-price
/// with ratio lanes, or second-price with regions and mask providers.
/// @notice Anyone requests an auction through Interfold and chooses its type in `customParams`. A
/// bidder encrypts SIMD ciphertexts to the E3's committee key and submits them in one call, with one
/// proof: role 0 `ge` (`[b >= level]`), role 1 `gt` (`[b > level]`) and role 2 `mask` (uniform
/// random). The second-price ratio type needs a fourth role, role 3 `pairMask` (uniform random,
/// equal in the two slots of each lane pair). The FHE program reads the ciphertexts of a bidder in
/// role order. The region types (0, 1) reveal only the winner and the price, as a pattern of zero
/// slots. The ratio types (2, 3) reveal the price and the set of bidders whose bid equals it. On a
/// top tie the bidder whose counted bid came first (lowest leaf) wins. See `program/src/lib.rs`.
///
/// The type 4 ("second-price, zero failure") gives the same result as the type 1, but a bidder sends
/// only `ge` and `gt`. The mask is the product of the masks of 1 to `MAX_PROVIDERS` providers, whom
/// the creator names at creation. Each provider sends one ciphertext, its mask, with a proof that
/// every one of its 128 slots is nonzero. While one provider is honest, the output slots are uniform.
/// The contract refuses every bid of a type-4 auction (`MasksPending`) until every provider has sent
/// its mask. The leaves are: the configuration leaf, the masks in the order they arrive, then the bids.
///
/// Leaf 0 of every auction is its configuration leaf: `keccak256(configInput)`, reduced into the
/// BN254 scalar field, where `configInput` is `CONFIG_DOMAIN || auctionType || provider_1 || ... ||
/// provider_k` (no provider for the types 0 to 3). The program reads the type and the providers
/// from the configuration input at that leaf, so the compute proof binds them through the input root.
///
/// One proof (`auction_bid2`, `auction_bid3` or `auction_bid4`) covers all ciphertexts of a bid. It
/// shows that each ciphertext is a valid encryption for its role under this E3's committee key, that
/// the roles 0 and 1 come from one bid `b < levels`, and which commitment each ciphertext has. Its
/// public inputs are the ciphertext commitments, the bidder, `levels`, the committee key commitment
/// and the VK anchor. A proof is bound to its bidder: a copy of another bidder's proof, for another
/// address, fails. A mask proof (`auction_mask`) has the public inputs: the commitment, the
/// provider, the committee key commitment and the VK anchor.
///
/// A bidder is an address. It may bid up to `MAX_BIDS_PER_BIDDER` times (a bid and updates). Each bid
/// is one run of `roleCount` consecutive leaves, in role order. The program counts the latest version of a
/// bidder whose ciphertexts open their commitments. A bid is sent by the bidder, or by a relayer with
/// the bidder's EIP-712 signature. An auction can name a gate (`IBidderGate`) that decides which
/// addresses may bid. A provider of a type-4 auction does not bid.
///
/// The contract cannot check that the published bytes open their commitments. The leaf binds the
/// bytes and the commitment together, and the program checks them.
contract AuctionProgram is IE3Program, IE3ProgramDataAvailability, IERC165, Ownable, EIP712 {
  using InternalLazyIMT for LazyIMTData;

  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  uint8 public constant TREE_DEPTH = 20;

  uint8 public constant ROLE_GE = 0;
  uint8 public constant ROLE_GT = 1;
  uint8 public constant ROLE_MASK = 2;
  /// @notice The mask of the second-price ratio auction.
  uint8 public constant ROLE_PAIR_MASK = 3;
  /// @notice The most roles of any auction type.
  uint8 public constant MAX_ROLES = 4;

  uint8 public constant AUCTION_FIRST_PRICE = 0;
  uint8 public constant AUCTION_SECOND_PRICE = 1;
  uint8 public constant AUCTION_RATIO_FIRST_PRICE = 2;
  uint8 public constant AUCTION_RATIO_SECOND_PRICE = 3;
  /// @notice Second-price auction (regions) whose random mask comes from 1 to `MAX_PROVIDERS` providers.
  uint8 public constant AUCTION_PROVIDER_SECOND_PRICE = 4;
  uint256 public constant MAX_TITLE_BYTES = 80;
  /// @notice The price steps of the program's slot layout: a bid is a step in `[0, LEVELS)`. An
  /// auction uses the first `levels` of them.
  uint8 public constant LEVELS = 16;
  /// @notice The fewest price steps of an auction.
  uint8 public constant MIN_LEVELS = 2;
  /// @notice The most bids of one bidder: the first bid and two updates.
  uint32 public constant MAX_BIDS_PER_BIDDER = 3;
  /// @notice The most mask providers of a type-4 auction.
  uint8 public constant MAX_PROVIDERS = 4;
  /// @notice The version in the metadata of a mask leaf: `provider || uint40 MASK_VERSION`. It is above
  /// every bid version, so a mask never counts as a bid.
  uint32 public constant MASK_VERSION = type(uint32).max;
  /// @notice The prefix of the configuration input. `shared/layout.ts` and the program use the same bytes.
  bytes public constant CONFIG_DOMAIN = "interfold-auction-config-v1";
  /// @notice The EIP-712 type of a relayed bid.
  bytes32 public constant BID_TYPEHASH = keccak256("Bid(uint256 e3Id,address bidder,uint32 version,bytes32 inputsHash)");
  uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// @notice The configuration of one auction, from the request's `customParams`.
  struct Auction {
    uint8 auctionType;
    /// @dev The number of price steps the creator chose, in `[MIN_LEVELS, LEVELS]`. A bid is a step
    /// below it, and the bid circuit enforces that: `levels` is a public input of the proof.
    uint8 levels;
    /// @dev The E3 requester.
    address creator;
    string title;
    /// @dev The bidder gate, or zero when anyone may bid.
    address gate;
    /// @dev The price of each step, strictly increasing for the first `levels` steps and zero after.
    /// The program sees only steps; a bid of step `b` means `prices[b]`. The public getter omits
    /// arrays: it returns `(auctionType, levels, creator, title, gate)`. Read the prices with
    /// `auctionPrices` and the providers with `auctionProviders`.
    uint256[LEVELS] prices;
    /// @dev The mask providers of a type-4 auction; empty for the other types.
    address[] providers;
  }

  /// @dev What `publishInput` decodes from its `data`.
  struct BidInput {
    address bidder;
    bytes[] ciphertexts;
    bytes32[] commitments;
    bytes proof;
    bytes gateProof;
    bytes signature;
  }

  IInterfold public interfold;
  IOpenVmReceiptVerifier public verifier;
  bytes32 public imageId;
  /// @notice Verifies the bid proof of the type with 2 roles (`auction_bid2`).
  IBidVerifier public immutable bidVerifier2;
  /// @notice Verifies the bid proof of the types with 3 roles (`auction_bid3`).
  IBidVerifier public immutable bidVerifier3;
  /// @notice Verifies the bid proof of the type with 4 roles (`auction_bid4`).
  IBidVerifier public immutable bidVerifier4;
  /// @notice Verifies the mask proof of a provider (`auction_mask`).
  IBidVerifier public immutable maskVerifier;
  /// @notice The VK chain of the circuits a 2-role bid proof passes through, as `auction_bid2` returns it.
  bytes32 public immutable vkAnchor2;
  /// @notice The VK chain of the circuits a 3-role bid proof passes through, as `auction_bid3` returns it.
  bytes32 public immutable vkAnchor3;
  /// @notice The VK chain of the circuits a 4-role bid proof passes through, as `auction_bid4` returns it.
  bytes32 public immutable vkAnchor4;
  /// @notice The VK chain of the circuits a mask proof passes through, as `auction_mask` returns it.
  bytes32 public immutable vkAnchorMask;
  /// @notice Verifies the availability receipt of the ciphertext output: the mock locally, Avail
  /// VectorX on a public network.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;

  mapping(address => bool) public authorizedContracts;
  mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
  mapping(uint256 e3Id => LazyIMTData) public inputs;
  /// @notice The bids of an address in an auction. The next bid has the version `bidCount + 1`.
  mapping(uint256 e3Id => mapping(address bidder => uint32)) public bidCount;
  /// @notice The addresses that have bid in an auction.
  mapping(uint256 e3Id => uint256) public bidderCount;
  mapping(uint256 e3Id => Auction) public auctions;
  /// @notice Whether an address is a mask provider of the type-4 auction of `e3Id`.
  mapping(uint256 e3Id => mapping(address provider => bool)) public isProvider;
  /// @notice Whether a provider has submitted its mask to the auction of `e3Id`.
  mapping(uint256 e3Id => mapping(address provider => bool)) public maskSubmitted;
  /// @notice The masks submitted to the auction of `e3Id`. Bids are open when it equals the number of providers.
  mapping(uint256 e3Id => uint256) public maskCount;

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
  error InvalidBidShape();
  error BidderIsZero();
  error SenderNotBidder(address sender, address bidder);
  error InvalidSignature(address bidder);
  error BidderNotEligible(address bidder);
  error TooManyBidders();
  error TooManyBids(address bidder);
  error InvalidBidProof();
  error UnknownAuctionType(uint8 auctionType);
  error InvalidTitle();
  error InvalidPrices();
  error InvalidLevels();
  error InvalidGate();
  error GateConfigWithoutGate();
  error InvalidProviders();
  error InvalidMaskProof();
  error MaskAlreadySubmitted(address provider);
  error MasksPending();

  /// @notice An auction was requested. Leaf 0 of its tree is the configuration leaf.
  /// @dev `gate` is zero when anyone may bid; then `gateConfig` is empty.
  event AuctionCreated(
    uint256 indexed e3Id,
    address indexed creator,
    uint8 auctionType,
    uint8 levels,
    uint256[LEVELS] prices,
    string title,
    address gate,
    bytes gateConfig
  );
  /// @notice A bidder submitted a bid, or an update of it. The ciphertexts are published here once.
  /// They occupy the leaves `firstIndex` to `firstIndex + ciphertexts.length - 1`, in role order.
  event BidSubmitted(
    uint256 indexed e3Id,
    address indexed bidder,
    uint32 version,
    uint256 firstIndex,
    bytes[] ciphertexts,
    bytes32[] commitments
  );
  /// @notice The providers of a type-4 auction, in the order the creator named them. Follows
  /// `AuctionCreated`.
  event MaskProvidersSet(uint256 indexed e3Id, address[] providers);
  /// @notice A provider submitted its mask. The ciphertext is published here once. It is the leaf
  /// `index` of the tree, with the metadata `provider || MASK_VERSION`.
  event MaskSubmitted(uint256 indexed e3Id, address indexed provider, uint256 index, bytes ciphertext, bytes32 commitment);

  /// @param _interfold The Interfold contract address
  /// @param _verifier The OpenVM receipt verifier address
  /// @param _imageId The receipt identity: `imageId()` of the OpenVM receipt verifier.
  /// @param _bidVerifier2 The generated verifier of `auction_bid2`
  /// @param _bidVerifier3 The generated verifier of `auction_bid3`
  /// @param _bidVerifier4 The generated verifier of `auction_bid4`
  /// @param _maskVerifier The generated verifier of `auction_mask`
  /// @param _vkAnchor2 The anchor `scripts/compile_circuits.sh` computed for `auction_bid2` (`vkAnchor2`)
  /// @param _vkAnchor3 The anchor `scripts/compile_circuits.sh` computed for `auction_bid3` (`vkAnchor3`)
  /// @param _vkAnchor4 The anchor `scripts/compile_circuits.sh` computed for `auction_bid4` (`vkAnchor4`)
  /// @param _vkAnchorMask The anchor `scripts/compile_circuits.sh` computed for `auction_mask` (`vkAnchorMask`)
  /// @param _dataAvailabilityVerifier The verifier of the output's availability receipt
  constructor(
    IInterfold _interfold,
    IOpenVmReceiptVerifier _verifier,
    bytes32 _imageId,
    IBidVerifier _bidVerifier2,
    IBidVerifier _bidVerifier3,
    IBidVerifier _bidVerifier4,
    IBidVerifier _maskVerifier,
    bytes32 _vkAnchor2,
    bytes32 _vkAnchor3,
    bytes32 _vkAnchor4,
    bytes32 _vkAnchorMask,
    IDataAvailabilityVerifier _dataAvailabilityVerifier
  ) Ownable(msg.sender) EIP712("AuctionProgram", "1") {
    require(address(_verifier) != address(0), VerifierAddressZero());
    require(address(_bidVerifier2) != address(0) && address(_bidVerifier3) != address(0), VerifierAddressZero());
    require(address(_bidVerifier4) != address(0) && address(_maskVerifier) != address(0), VerifierAddressZero());
    require(address(_dataAvailabilityVerifier).code.length != 0, InvalidDataAvailabilityVerifier());
    require(_imageId == _verifier.imageId(), InvalidImageId());
    interfold = _interfold;
    verifier = _verifier;
    imageId = _imageId;
    bidVerifier2 = _bidVerifier2;
    bidVerifier3 = _bidVerifier3;
    bidVerifier4 = _bidVerifier4;
    maskVerifier = _maskVerifier;
    vkAnchor2 = _vkAnchor2;
    vkAnchor3 = _vkAnchor3;
    vkAnchor4 = _vkAnchor4;
    vkAnchorMask = _vkAnchorMask;
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

  /// @inheritdoc IE3Program
  /// @dev `customParams` is `abi.encode(uint8 auctionType, uint8 levels, uint256[16] prices, string title,
  /// address gate, bytes gateConfig, address[] providers)`. `prices[levels..16]` must be zero. With
  /// `gate == address(0)` anyone may bid and `gateConfig` must be empty. Otherwise the gate is
  /// configured with `gateConfig`. `providers` is empty for the types 0 to 3. For the type 4 it names
  /// 1 to `MAX_PROVIDERS` distinct nonzero mask providers (else `InvalidProviders`).
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
    (uint256 leaf, address gate, bytes memory gateConfig) = _initAuction(e3Id, customParams);
    LazyIMTData storage tree = inputs[e3Id];
    tree._init(TREE_DEPTH);
    tree._insert(leaf);
    if (gate != address(0)) IBidderGate(gate).configure(e3Id, gateConfig);
    return ENCRYPTION_SCHEME_ID;
  }

  /// @dev Decodes, checks and stores the auction of `e3Id`. Returns its configuration leaf.
  function _initAuction(uint256 e3Id, bytes calldata customParams) private returns (uint256 leaf, address gate, bytes memory gateConfig) {
    Auction memory auction;
    (auction, gateConfig) = _decodeParams(customParams);
    _checkParams(auction, gateConfig);
    auction.creator = interfold.getE3(e3Id).requester;
    auctions[e3Id] = auction;
    emit AuctionCreated(
      e3Id,
      auction.creator,
      auction.auctionType,
      auction.levels,
      auction.prices,
      auction.title,
      auction.gate,
      gateConfig
    );
    if (auction.auctionType == AUCTION_PROVIDER_SECOND_PRICE) {
      for (uint256 i = 0; i < auction.providers.length; i++) {
        isProvider[e3Id][auction.providers[i]] = true;
      }
      emit MaskProvidersSet(e3Id, auction.providers);
    }
    return (configLeaf(auction.auctionType, auction.providers), auction.gate, gateConfig);
  }

  function _decodeParams(bytes calldata customParams) private pure returns (Auction memory auction, bytes memory gateConfig) {
    // A type expression in `abi.decode` needs a literal length; it is `LEVELS`.
    (auction.auctionType, auction.levels, auction.prices, auction.title, auction.gate, gateConfig, auction.providers) = abi.decode(
      customParams,
      (uint8, uint8, uint256[16], string, address, bytes, address[])
    );
  }

  function _checkParams(Auction memory auction, bytes memory gateConfig) private view {
    if (auction.auctionType > AUCTION_PROVIDER_SECOND_PRICE) revert UnknownAuctionType(auction.auctionType);
    if (auction.levels < MIN_LEVELS || auction.levels > LEVELS) revert InvalidLevels();
    for (uint256 level = 1; level < auction.levels; level++) {
      if (auction.prices[level] <= auction.prices[level - 1]) revert InvalidPrices();
    }
    // The steps the creator did not choose are empty, so the stored list is canonical.
    for (uint256 level = auction.levels; level < LEVELS; level++) {
      if (auction.prices[level] != 0) revert InvalidPrices();
    }
    uint256 titleBytes = bytes(auction.title).length;
    if (titleBytes == 0 || titleBytes > MAX_TITLE_BYTES) revert InvalidTitle();
    if (auction.gate == address(0)) {
      if (gateConfig.length != 0) revert GateConfigWithoutGate();
    } else if (auction.gate.code.length == 0) {
      revert InvalidGate();
    }
    _checkProviders(auction.auctionType, auction.providers);
  }

  /// @dev The type 4 needs 1 to `MAX_PROVIDERS` providers, each nonzero and unique. The other types
  /// have none.
  function _checkProviders(uint8 auctionType, address[] memory providers) private pure {
    if (auctionType != AUCTION_PROVIDER_SECOND_PRICE) {
      if (providers.length != 0) revert InvalidProviders();
      return;
    }
    if (providers.length == 0 || providers.length > MAX_PROVIDERS) revert InvalidProviders();
    for (uint256 i = 0; i < providers.length; i++) {
      if (providers[i] == address(0)) revert InvalidProviders();
      for (uint256 j = 0; j < i; j++) {
        if (providers[i] == providers[j]) revert InvalidProviders();
      }
    }
  }

  /// @notice The price of each bid level of the auction of `e3Id`.
  function auctionPrices(uint256 e3Id) external view returns (uint256[LEVELS] memory) {
    return auctions[e3Id].prices;
  }

  /// @notice The mask providers of the auction of `e3Id`: the addresses a type-4 creator named, in
  /// the order of the masks. Empty for the types 0 to 3.
  function auctionProviders(uint256 e3Id) external view returns (address[] memory) {
    return auctions[e3Id].providers;
  }

  /// @notice The number of ciphertexts one bidder submits to an auction of `auctionType`: 2 (`ge`,
  /// `gt`) for the type 4, 3 (`ge`, `gt`, `mask`) for the types 0 to 2, or 4 for the second-price
  /// ratio auction (and the `pairMask`). A provider's mask of a type-4 auction is one ciphertext.
  function roleCount(uint8 auctionType) public pure returns (uint8) {
    if (auctionType > AUCTION_PROVIDER_SECOND_PRICE) revert UnknownAuctionType(auctionType);
    if (auctionType == AUCTION_RATIO_SECOND_PRICE) return 4;
    return auctionType == AUCTION_PROVIDER_SECOND_PRICE ? 2 : 3;
  }

  /// @notice The most bidders in one E3 of `auctionType`: 4 for the types 0 and 1, 8 for the types
  /// 2 to 4. It is the most the program's slot layout supports. The providers of a type-4 auction
  /// are not bidders.
  function maxBidders(uint8 auctionType) public pure returns (uint8) {
    if (auctionType > AUCTION_PROVIDER_SECOND_PRICE) revert UnknownAuctionType(auctionType);
    return auctionType >= AUCTION_RATIO_FIRST_PRICE ? 8 : 4;
  }

  /// @notice The configuration input of an auction of `auctionType`: `CONFIG_DOMAIN || uint8 type ||
  /// provider_1 || ... || provider_k`, each provider as its 20 raw bytes (not the 32-byte words of
  /// `abi.encodePacked(address[])`). The types 0 to 3 have no providers, so their input is the domain
  /// and the type. The program reads the same bytes.
  function configInput(uint8 auctionType, address[] memory providers) public pure returns (bytes memory input) {
    input = abi.encodePacked(CONFIG_DOMAIN, auctionType);
    for (uint256 i = 0; i < providers.length; i++) {
      input = bytes.concat(input, bytes20(providers[i]));
    }
  }

  /// @notice Leaf 0 of an auction of `auctionType`: the configuration input, hashed into the field.
  function configLeaf(uint8 auctionType, address[] memory providers) public pure returns (uint256) {
    return uint256(keccak256(configInput(auctionType, providers))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The leaf of one ciphertext of a bid. The program computes the same value from the
  /// published bytes and the 25 bytes of metadata `bidder || uint40 version`.
  /// @param ciphertextHash `keccak256` of the ciphertext bytes.
  /// @param commitment The SAFE commitment of the ciphertext, which the bid proof binds.
  function inputLeaf(bytes32 ciphertextHash, bytes32 commitment, address bidder, uint32 version) public pure returns (uint256) {
    return uint256(sha256(abi.encodePacked(ciphertextHash, commitment, bidder, uint40(version)))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The EIP-712 digest that a bidder signs to let a relayer send a bid.
  /// @param version The version the bid will get: `bidCount + 1`.
  /// @param inputsHash `keccak256(abi.encode(commitments, ciphertextHashes))`.
  function bidDigest(uint256 e3Id, address bidder, uint32 version, bytes32 inputsHash) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(BID_TYPEHASH, e3Id, bidder, version, inputsHash)));
  }

  /// @notice Submit a bid, or an update of the bidder's earlier bid. In a type-4 auction a provider
  /// submits its mask the same way (see `_publishMask`), and a bid is refused until every provider has.
  /// @param data `abi.encode(address bidder, bytes[] ciphertexts, bytes32[] commitments, bytes proof,
  /// bytes gateProof, bytes signature)`. With an empty `signature` the sender must be `bidder`.
  /// Otherwise `signature` is the bidder's EIP-712 signature (`bidDigest`), and anyone may send.
  /// A mask has one ciphertext and commitment, `bidder` is the provider, and `gateProof` and
  /// `signature` are empty: only the provider sends it.
  function publishInput(uint256 e3Id, bytes memory data) external override {
    E3 memory e3 = interfold.getE3(e3Id);
    if (block.timestamp > e3.inputWindow[1]) revert InputDeadlineReached();
    BidInput memory bid;
    (bid.bidder, bid.ciphertexts, bid.commitments, bid.proof, bid.gateProof, bid.signature) = abi.decode(
      data,
      (address, bytes[], bytes32[], bytes, bytes, bytes)
    );
    Auction storage auction = auctions[e3Id];
    if (auction.auctionType == AUCTION_PROVIDER_SECOND_PRICE) {
      if (isProvider[e3Id][bid.bidder]) {
        _publishMask(e3Id, bid, e3.committeePublicKey);
        return;
      }
      if (maskCount[e3Id] != auction.providers.length) revert MasksPending();
    }
    uint8 roles = roleCount(auction.auctionType);
    if (bid.ciphertexts.length != roles || bid.commitments.length != roles) revert InvalidBidShape();
    if (bid.bidder == address(0)) revert BidderIsZero();

    bytes32[] memory hashes = new bytes32[](roles);
    for (uint256 r = 0; r < roles; r++) {
      if (bid.ciphertexts[r].length == 0) revert EmptyInputData();
      hashes[r] = keccak256(bid.ciphertexts[r]);
    }

    uint32 version = _nextVersion(e3Id, bid.bidder, auction.auctionType);
    _checkSender(e3Id, bid, version, hashes);
    if (auction.gate != address(0) && !IBidderGate(auction.gate).isEligible(e3Id, bid.bidder, bid.gateProof)) {
      revert BidderNotEligible(bid.bidder);
    }
    _verifyBidProof(bid, roles, auction.levels, e3.committeePublicKey);

    uint256 firstIndex = _insertLeaves(e3Id, bid, hashes, version);
    emit BidSubmitted(e3Id, bid.bidder, version, firstIndex, bid.ciphertexts, bid.commitments);
  }

  /// @dev The mask of a provider of a type-4 auction: one ciphertext, sent by the provider. It takes
  /// the next leaf, after the configuration leaf and the masks before it, with the metadata
  /// `provider || MASK_VERSION`. No gate and no signature apply: a provider is named in the
  /// auction's configuration and sends its own mask. Public inputs: the commitment, the provider,
  /// the committee key commitment and `vkAnchorMask`.
  function _publishMask(uint256 e3Id, BidInput memory mask, bytes32 committeePublicKey) private {
    if (mask.ciphertexts.length != 1 || mask.commitments.length != 1 || mask.gateProof.length != 0 || mask.signature.length != 0)
      revert InvalidBidShape();
    if (mask.ciphertexts[0].length == 0) revert EmptyInputData();
    if (mask.bidder != msg.sender) revert SenderNotBidder(msg.sender, mask.bidder);
    if (maskSubmitted[e3Id][mask.bidder]) revert MaskAlreadySubmitted(mask.bidder);

    bytes32[] memory publicInputs = new bytes32[](4);
    publicInputs[0] = mask.commitments[0];
    publicInputs[1] = bytes32(uint256(uint160(mask.bidder)));
    publicInputs[2] = committeePublicKey;
    publicInputs[3] = vkAnchorMask;
    if (!maskVerifier.verify(mask.proof, publicInputs)) revert InvalidMaskProof();

    maskSubmitted[e3Id][mask.bidder] = true;
    maskCount[e3Id]++;
    LazyIMTData storage tree = inputs[e3Id];
    uint256 index = tree.numberOfLeaves;
    tree._insert(inputLeaf(keccak256(mask.ciphertexts[0]), mask.commitments[0], mask.bidder, MASK_VERSION));
    emit MaskSubmitted(e3Id, mask.bidder, index, mask.ciphertexts[0], mask.commitments[0]);
  }

  /// @dev Counts the bid: the version of the bidder's next bid, and a new bidder takes a place.
  function _nextVersion(uint256 e3Id, address bidder, uint8 auctionType) private returns (uint32 version) {
    version = bidCount[e3Id][bidder] + 1;
    if (version > MAX_BIDS_PER_BIDDER) revert TooManyBids(bidder);
    if (version == 1) {
      uint256 bidders = bidderCount[e3Id];
      if (bidders >= maxBidders(auctionType)) revert TooManyBidders();
      bidderCount[e3Id] = bidders + 1;
    }
    bidCount[e3Id][bidder] = version;
  }

  /// @dev A direct bid comes from its bidder. A relayed bid carries the bidder's signature over the
  /// version and the hash of the exact commitments and ciphertexts, so a relayer cannot swap bytes
  /// and an old signature is useless once the bidder has bid again.
  function _checkSender(uint256 e3Id, BidInput memory bid, uint32 version, bytes32[] memory hashes) private view {
    if (bid.signature.length == 0) {
      if (bid.bidder != msg.sender) revert SenderNotBidder(msg.sender, bid.bidder);
      return;
    }
    bytes32 inputsHash = keccak256(abi.encode(bid.commitments, hashes));
    if (!SignatureChecker.isValidSignatureNow(bid.bidder, bidDigest(e3Id, bid.bidder, version, inputsHash), bid.signature)) {
      revert InvalidSignature(bid.bidder);
    }
  }

  /// @dev Public inputs: the ciphertext commitments in role order, the bidder, `levels`, the
  /// committee key commitment and the VK anchor. The verifier follows the role count: `auction_bid2`
  /// for 2 roles, `auction_bid3` for 3 and `auction_bid4` for 4.
  function _verifyBidProof(BidInput memory bid, uint8 roles, uint8 levels, bytes32 committeePublicKey) private view {
    bytes32[] memory publicInputs = new bytes32[](roles + 4);
    for (uint256 r = 0; r < roles; r++) {
      publicInputs[r] = bid.commitments[r];
    }
    publicInputs[roles] = bytes32(uint256(uint160(bid.bidder)));
    publicInputs[roles + 1] = bytes32(uint256(levels));
    publicInputs[roles + 2] = committeePublicKey;
    IBidVerifier bidVerifier;
    bytes32 vkAnchor;
    if (roles == 2) {
      (bidVerifier, vkAnchor) = (bidVerifier2, vkAnchor2);
    } else if (roles == MAX_ROLES) {
      (bidVerifier, vkAnchor) = (bidVerifier4, vkAnchor4);
    } else {
      (bidVerifier, vkAnchor) = (bidVerifier3, vkAnchor3);
    }
    publicInputs[roles + 3] = vkAnchor;
    if (!bidVerifier.verify(bid.proof, publicInputs)) revert InvalidBidProof();
  }

  /// @dev Inserts the leaves of a bid as consecutive leaves in role order and returns the first index.
  function _insertLeaves(uint256 e3Id, BidInput memory bid, bytes32[] memory hashes, uint32 version) private returns (uint256 firstIndex) {
    LazyIMTData storage tree = inputs[e3Id];
    firstIndex = tree.numberOfLeaves;
    for (uint256 r = 0; r < hashes.length; r++) {
      tree._insert(inputLeaf(hashes[r], bid.commitments[r], bid.bidder, version));
    }
  }

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
