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
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { IRecordVerifier } from "./interfaces/IRecordVerifier.sol";

/// @title Sealed-bid auction: first-price or second-price (Vickrey) with regions, or first-price or
/// second-price with ratio lanes.
/// @notice Anyone requests an auction through Interfold and chooses its type in `customParams`. A
/// bidder encrypts SIMD ciphertexts to the E3's committee key and submits them one at a time, each
/// with its own proof: role 0 `ge` (`[b >= level]`), role 1 `gt` (`[b > level]`) and role 2 `mask`
/// (uniform random). The second-price ratio type needs a fourth role, role 3 `pairMask` (uniform
/// random, equal in the two slots of each lane pair). The FHE program reads the ciphertexts of a
/// bidder in role order. The region types (0, 1) reveal only the winner and the price, as a pattern
/// of zero slots. The ratio types (2, 3) reveal the price, the set of bidders whose bid equals it,
/// and one random value that picks the winner from that set. See `program/src/lib.rs`.
///
/// Leaf 0 of every auction is its configuration leaf: `keccak256(CONFIG_DOMAIN || auctionType)`
/// reduced into the BN254 scalar field. The program reads the type from the configuration input at
/// that leaf, so the compute proof binds the type through the input root.
///
/// Every ciphertext carries a proof (`circuits/fold`) that it encrypts a valid ciphertext for its
/// role under this E3's committee key. For the roles 0 and 1 the proof also exposes the bid
/// commitment `poseidon2(b, salt)`, so a bidder can only submit two thermometers of one bid. A bid
/// enters the computation only once all roles of its auction type are in (`roleCount`), and their
/// ciphertext commitments become consecutive leaves in role order: leaf `1 + roleCount * i + r` is
/// role `r` of the `i`-th linked bidder.
///
/// The proof binds the sender: the contract passes `msg.sender` as a public input. A copy of
/// another bidder's proof, from another address, fails verification. Without this, a copy of the
/// highest bidder's thermometers would tie that bid, and the price would show it.
///
/// Anyone can bid, from any address, up to `maxBidders` bidders for one E3. A bidder is the
/// address that submits. An address that bids twice would be two bidders in the program, so each
/// address can submit each role once.
contract AuctionProgram is IE3Program, IE3ProgramDataAvailability, IERC165, Ownable {
  using InternalLazyIMT for LazyIMTData;

  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  uint8 public constant TREE_DEPTH = 20;

  uint8 public constant ROLE_GE = 0;
  uint8 public constant ROLE_GT = 1;
  uint8 public constant ROLE_MASK = 2;
  /// @notice The mask of the second-price ratio auction. It has no bid commitment, like `ROLE_MASK`.
  uint8 public constant ROLE_PAIR_MASK = 3;
  /// @notice The most roles of any auction type.
  uint8 public constant MAX_ROLES = 4;

  uint8 public constant AUCTION_FIRST_PRICE = 0;
  uint8 public constant AUCTION_SECOND_PRICE = 1;
  uint8 public constant AUCTION_RATIO_FIRST_PRICE = 2;
  uint8 public constant AUCTION_RATIO_SECOND_PRICE = 3;
  uint256 public constant MAX_TITLE_BYTES = 80;
  /// @notice The bid levels of the program's slot layout: a bid is a level in `[0, LEVELS)`.
  uint8 public constant LEVELS = 16;
  /// @notice The prefix of the configuration input. `shared/layout.ts` and the program use the same bytes.
  bytes public constant CONFIG_DOMAIN = "interfold-auction-config-v1";
  uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// @notice The configuration of one auction, from the request's `customParams`.
  struct Auction {
    uint8 auctionType;
    /// @dev The E3 requester.
    address creator;
    string title;
    /// @dev The price of each bid level, strictly increasing. The program sees only levels; a bid
    /// of level `b` means `prices[b]`. The public getter omits arrays: read it with `auctionPrices`.
    uint256[LEVELS] prices;
  }

  IInterfold public interfold;
  IOpenVmReceiptVerifier public verifier;
  bytes32 public imageId;
  /// @notice Verifies the per-ciphertext fold proof.
  IRecordVerifier public immutable recordVerifier;
  /// @notice The VK chain of every circuit a proof passes through, as `auction_fold` returns it.
  bytes32 public immutable vkAnchor;
  /// @notice Verifies the availability receipt of the ciphertext output: the mock locally, Avail
  /// VectorX on a public network.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;

  /// @notice What a bidder has submitted until all roles of the auction type are in.
  struct PendingBid {
    bytes32[MAX_ROLES] ciphertextCommitments;
    /// @dev The bid commitment of role 0 or 1, whichever came first. Zero until then.
    bytes32 bidCommitment;
    /// @dev Bit `r` is set once role `r` has been submitted.
    uint8 submittedRoles;
  }

  mapping(address => bool) public authorizedContracts;
  mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
  mapping(uint256 e3Id => LazyIMTData) public inputs;
  mapping(uint256 e3Id => mapping(address bidder => PendingBid)) internal _pending;
  /// @notice The bidders whose ciphertexts (all roles of the auction type) are in the tree.
  mapping(uint256 e3Id => uint256) public linkedBidders;
  mapping(uint256 e3Id => Auction) public auctions;

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
  error UnknownRole(uint8 role);
  error RoleAlreadySubmitted(address bidder, uint8 role);
  error TooManyBidders();
  error InvalidBidCommitment(uint8 role);
  error BidCommitmentMismatch(address bidder);
  error InvalidRecordProof();
  error UnknownAuctionType(uint8 auctionType);
  error InvalidTitle();
  error InvalidPrices();

  /// @notice An auction was requested. Leaf 0 of its tree is the configuration leaf.
  event AuctionCreated(uint256 indexed e3Id, address indexed creator, uint8 auctionType, uint256[LEVELS] prices, string title);
  /// @notice A bidder submitted one ciphertext. The ciphertext is published here once.
  event BidSubmitted(uint256 indexed e3Id, address indexed bidder, uint8 role, bytes ciphertext, bytes32 ciphertextCommitment);
  /// @notice All ciphertexts of a bidder are in; they occupy the leaves `firstIndex` to `firstIndex + roleCount - 1`.
  event BidLinked(uint256 indexed e3Id, address indexed bidder, uint256 firstIndex);

  /// @param _interfold The Interfold contract address
  /// @param _verifier The OpenVM receipt verifier address
  /// @param _imageId The receipt identity: `imageId()` of the OpenVM receipt verifier.
  /// @param _recordVerifier The generated verifier of `circuits/fold`
  /// @param _vkAnchor The anchor `scripts/compile_circuits.sh` computed for the same circuits
  /// @param _dataAvailabilityVerifier The verifier of the output's availability receipt
  constructor(
    IInterfold _interfold,
    IOpenVmReceiptVerifier _verifier,
    bytes32 _imageId,
    IRecordVerifier _recordVerifier,
    bytes32 _vkAnchor,
    IDataAvailabilityVerifier _dataAvailabilityVerifier
  ) Ownable(msg.sender) {
    require(address(_verifier) != address(0) && address(_recordVerifier) != address(0), VerifierAddressZero());
    require(address(_dataAvailabilityVerifier).code.length != 0, InvalidDataAvailabilityVerifier());
    require(_imageId == _verifier.imageId(), InvalidImageId());
    interfold = _interfold;
    verifier = _verifier;
    imageId = _imageId;
    recordVerifier = _recordVerifier;
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

  /// @inheritdoc IE3Program
  /// @dev `customParams` is `abi.encode(uint8 auctionType, uint256[16] prices, string title)`.
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
    uint8 auctionType = _initAuction(e3Id, customParams);
    LazyIMTData storage tree = inputs[e3Id];
    tree._init(TREE_DEPTH);
    tree._insert(configLeaf(auctionType));
    return ENCRYPTION_SCHEME_ID;
  }

  /// @dev Decodes, checks and stores the auction of `e3Id`, and returns its type.
  function _initAuction(uint256 e3Id, bytes calldata customParams) private returns (uint8 auctionType) {
    uint256[LEVELS] memory prices;
    string memory title;
    // A type expression in `abi.decode` needs a literal length; it is `LEVELS`.
    (auctionType, prices, title) = abi.decode(customParams, (uint8, uint256[16], string));
    if (auctionType > AUCTION_RATIO_SECOND_PRICE) revert UnknownAuctionType(auctionType);
    for (uint256 level = 1; level < LEVELS; level++) {
      if (prices[level] <= prices[level - 1]) revert InvalidPrices();
    }
    uint256 titleBytes = bytes(title).length;
    if (titleBytes == 0 || titleBytes > MAX_TITLE_BYTES) revert InvalidTitle();
    address creator = interfold.getE3(e3Id).requester;
    auctions[e3Id] = Auction(auctionType, creator, title, prices);
    emit AuctionCreated(e3Id, creator, auctionType, prices, title);
  }

  /// @notice The price of each bid level of the auction of `e3Id`.
  function auctionPrices(uint256 e3Id) external view returns (uint256[LEVELS] memory) {
    return auctions[e3Id].prices;
  }

  /// @notice The number of ciphertexts one bidder submits to an auction of `auctionType`: 3 (`ge`,
  /// `gt`, `mask`), or 4 for the second-price ratio auction (and the `pairMask`).
  function roleCount(uint8 auctionType) public pure returns (uint8) {
    if (auctionType > AUCTION_RATIO_SECOND_PRICE) revert UnknownAuctionType(auctionType);
    return auctionType == AUCTION_RATIO_SECOND_PRICE ? 4 : 3;
  }

  /// @notice The most bidders in one E3 of `auctionType`: 4 for the region types, 8 for the ratio
  /// types. It is the most the program's slot layout supports.
  function maxBidders(uint8 auctionType) public pure returns (uint8) {
    if (auctionType > AUCTION_RATIO_SECOND_PRICE) revert UnknownAuctionType(auctionType);
    return auctionType >= AUCTION_RATIO_FIRST_PRICE ? 8 : 4;
  }

  /// @notice Leaf 0 of an auction of `auctionType`: the configuration input, hashed into the field.
  function configLeaf(uint8 auctionType) public pure returns (uint256) {
    return uint256(keccak256(abi.encodePacked(CONFIG_DOMAIN, auctionType))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The roles a bidder has submitted, as a bit mask: bit `r` is role `r`. It is
  /// `2^roleCount - 1` (7 or 15) for a linked bidder.
  function submittedRoles(uint256 e3Id, address bidder) external view returns (uint8) {
    return _pending[e3Id][bidder].submittedRoles;
  }

  /// @notice Submit one ciphertext of the sender's bid.
  /// @param data `abi.encode(uint8 role, bytes ciphertext, bytes32 ciphertextCommitment, bytes32 bidCommitment, bytes proof)`.
  /// `bidCommitment` is `poseidon2(b, salt)` for the roles 0 and 1, and 0 for the masks (roles 2 and 3).
  function publishInput(uint256 e3Id, bytes memory data) external override {
    E3 memory e3 = interfold.getE3(e3Id);
    if (block.timestamp > e3.inputWindow[1]) revert InputDeadlineReached();
    // Only complete bids take a place. A bidder that does not finish blocks nobody; a bidder that
    // finishes after the places are full is rejected.
    uint8 roles;
    {
      uint8 auctionType = auctions[e3Id].auctionType;
      if (linkedBidders[e3Id] >= maxBidders(auctionType)) revert TooManyBidders();
      roles = roleCount(auctionType);
    }

    (uint8 role, bytes memory ciphertext, bytes32 ciphertextCommitment, bytes32 bidCommitment, bytes memory proof) = abi.decode(
      data,
      (uint8, bytes, bytes32, bytes32, bytes)
    );
    if (role >= roles) revert UnknownRole(role);
    if (ciphertext.length == 0) revert EmptyInputData();
    // The masks have no bid. The thermometers have one, which is never zero.
    if ((role >= ROLE_MASK) != (bidCommitment == bytes32(0))) revert InvalidBidCommitment(role);

    PendingBid storage pending = _pending[e3Id][msg.sender];
    uint8 submitted = pending.submittedRoles;
    if (submitted & (uint8(1) << role) != 0) revert RoleAlreadySubmitted(msg.sender, role);
    if (role < ROLE_MASK) {
      // Both thermometers must come from one bid. The second of them to arrive is checked.
      bytes32 other = pending.bidCommitment;
      if (other != bytes32(0) && other != bidCommitment) revert BidCommitmentMismatch(msg.sender);
      pending.bidCommitment = bidCommitment;
    }

    bytes32[] memory publicInputs = new bytes32[](6);
    publicInputs[0] = bytes32(uint256(role));
    publicInputs[1] = ciphertextCommitment;
    publicInputs[2] = bidCommitment;
    publicInputs[3] = bytes32(uint256(uint160(msg.sender)));
    publicInputs[4] = e3.committeePublicKey;
    publicInputs[5] = vkAnchor;
    if (!recordVerifier.verify(proof, publicInputs)) revert InvalidRecordProof();

    // The proof binds the commitment, not these bytes. As in the template, a bidder that publishes
    // bytes that do not open its commitment makes the input root unprovable and stalls the E3.
    pending.ciphertextCommitments[role] = ciphertextCommitment;
    submitted |= uint8(1) << role;
    pending.submittedRoles = submitted;
    emit BidSubmitted(e3Id, msg.sender, role, ciphertext, ciphertextCommitment);

    if (submitted == (uint8(1) << roles) - 1) _link(e3Id, pending, roles);
  }

  /// @dev Inserts the `roles` ciphertext commitments of a complete bid as consecutive leaves in role order.
  function _link(uint256 e3Id, PendingBid storage pending, uint8 roles) private {
    LazyIMTData storage tree = inputs[e3Id];
    uint256 firstIndex = tree.numberOfLeaves;
    for (uint256 r = 0; r < roles; r++) {
      tree._insert(uint256(pending.ciphertextCommitments[r]));
    }
    delete pending.ciphertextCommitments;
    linkedBidders[e3Id] += 1;
    emit BidLinked(e3Id, msg.sender, firstIndex);
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
