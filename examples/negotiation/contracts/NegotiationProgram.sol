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
import { IOfferVerifier } from "./interfaces/IOfferVerifier.sol";
import { NegotiationOutput } from "./libraries/NegotiationOutput.sol";

/// @title Sealed two-party price negotiation.
/// @notice A seller and a buyer settle one price without showing their limits. The price grid is public:
/// level `i` has the price `minPrice + i * stepPrice`, with up to 16 levels. The seller encrypts its
/// private minimum level `s`, and the buyer encrypts its private maximum level `b`, to the E3 committee
/// key. An offer is three ciphertexts and one proof. The FHE program combines the two offers and the
/// committee decrypts one output. If `b >= s`, the output names one level `p` that is almost uniform
/// in `[s, b]`. Otherwise it shows only that there is no match. Nobody learns `s` or `b`.
///
/// Flow: anyone requests the E3 and names the seller and, optionally, the buyer (`validate`). Each party
/// sends its offer with `publishInput`, directly or through a relayer with its EIP-712 signature. If the
/// buyer is the zero address, the buyer seat is open: the first wallet that is not the seller and that
/// sends a valid buyer offer becomes the buyer, for good. Any wallet that finds the negotiation can take
/// an open seat first, so use it only when that is acceptable. After the input window,
/// the program computes and Interfold publishes the plaintext. Anyone then calls `settle`, which reads
/// the level from the plaintext and stores the price. There is no deposit: a negotiation that one
/// party does not complete stops without a loss. `DESIGN.md` explains the encoding of the output.
contract NegotiationProgram is IE3Program, IE3ProgramDataAvailability, IERC165, Ownable, EIP712 {
  using InternalLazyIMT for LazyIMTData;

  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  /// @notice The configuration input of a negotiation. The program uses the same bytes.
  bytes public constant CONFIG_DOMAIN = "interfold-negotiation-config-v1";
  uint8 public constant TREE_DEPTH = 20;
  /// @notice The most price levels of a negotiation: the slots of one group of the output.
  uint8 public constant MAX_LEVELS = 16;
  uint8 public constant MIN_LEVELS = 2;
  /// @notice The role of the seller. The seller has the private minimum level.
  uint8 public constant SELLER = 0;
  /// @notice The role of the buyer. The buyer has the private maximum level.
  uint8 public constant BUYER = 1;
  /// @notice The ciphertexts of one offer: the lanes 0 to 7, the lanes 8 to 15 and the mask.
  uint256 public constant OFFER_CIPHERTEXTS = 3;
  /// @notice The EIP-712 type of a relayed offer.
  bytes32 public constant OFFER_TYPEHASH = keccak256("Offer(uint256 e3Id,address party,bytes32 inputsHash)");
  uint256 private constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 private constant PRICE_LIMIT = 1 << 128;

  /// @dev The public terms of a negotiation.
  struct Terms {
    address creator;
    address seller;
    /// @dev The zero address while the buyer seat is open. `publishInput` sets it once.
    address buyer;
    uint8 levels;
    uint256 minPrice;
    uint256 stepPrice;
    string title;
  }

  /// @dev The result of `settle`.
  struct Outcome {
    bool settled;
    bool matched;
    uint8 step;
    uint256 price;
  }

  /// @dev What `publishInput` decodes from its `data`.
  struct OfferInput {
    address party;
    bytes[] ciphertexts;
    bytes32[] commitments;
    bytes proof;
    bytes signature;
  }

  IInterfold public interfold;
  IOpenVmReceiptVerifier public verifier;
  bytes32 public imageId;
  /// @notice Verifies the offer proof (`negotiation_offer`).
  IOfferVerifier public immutable offerVerifier;
  /// @notice The VK chain of the circuits the offer proof passes through.
  bytes32 public immutable vkAnchor;
  /// @notice Verifies the availability receipt of the ciphertext output.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;

  mapping(address => bool) public authorizedContracts;
  mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
  mapping(uint256 e3Id => LazyIMTData) public inputs;
  /// @notice The terms of a negotiation.
  mapping(uint256 e3Id => Terms) public negotiation;
  /// @notice Whether the party of a role has sent its offer.
  mapping(uint256 e3Id => mapping(uint8 role => bool)) public offerSubmitted;
  mapping(uint256 e3Id => Outcome) private _outcome;

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
  error InvalidParties();
  error InvalidLevels(uint8 levels);
  error InvalidPrices();
  error NotAParty(address party);
  error SenderNotParty(address sender, address party);
  error InvalidSignature(address party);
  error InvalidOfferShape();
  error AlreadySubmitted(address party, uint8 role);
  error InvalidOfferProof();
  error OutputNotPublished();
  error AlreadySettled();

  /// @notice A negotiation was requested. Leaf 0 of its tree is the configuration leaf.
  event NegotiationCreated(
    uint256 indexed e3Id,
    address indexed creator,
    address indexed seller,
    address buyer,
    uint8 levels,
    uint256 minPrice,
    uint256 stepPrice,
    string title
  );
  /// @notice A party sent its offer. The ciphertexts are published here once. Their leaves are the
  /// leaves `firstLeaf` to `firstLeaf + 2` of the input tree, in order.
  event OfferSubmitted(
    uint256 indexed e3Id,
    address indexed party,
    uint8 role,
    uint256 firstLeaf,
    bytes[] ciphertexts,
    bytes32[] commitments
  );
  /// @notice The open buyer seat of a negotiation was taken by the first valid buyer offer. The buyer
  /// is fixed from then on. It is emitted with the `OfferSubmitted` event of the same offer.
  event BuyerJoined(uint256 indexed e3Id, address indexed buyer);
  /// @notice The outcome was read from the published plaintext. `step` and `price` are 0 for no match.
  event Settled(uint256 indexed e3Id, bool matched, uint8 step, uint256 price);

  /// @param _interfold The Interfold contract address
  /// @param _verifier The OpenVM receipt verifier address
  /// @param _imageId The receipt identity: `imageId()` of the OpenVM receipt verifier.
  /// @param _offerVerifier The generated verifier of `negotiation_offer`
  /// @param _vkAnchor The anchor of `negotiation_offer` (`circuits/target/vk_anchor.json`)
  /// @param _dataAvailabilityVerifier The verifier of the output's availability receipt
  constructor(
    IInterfold _interfold,
    IOpenVmReceiptVerifier _verifier,
    bytes32 _imageId,
    IOfferVerifier _offerVerifier,
    bytes32 _vkAnchor,
    IDataAvailabilityVerifier _dataAvailabilityVerifier
  ) Ownable(msg.sender) EIP712("NegotiationProgram", "1") {
    require(address(_verifier) != address(0) && address(_offerVerifier) != address(0), VerifierAddressZero());
    require(address(_dataAvailabilityVerifier).code.length != 0, InvalidDataAvailabilityVerifier());
    require(_imageId == _verifier.imageId(), InvalidImageId());
    interfold = _interfold;
    verifier = _verifier;
    imageId = _imageId;
    offerVerifier = _offerVerifier;
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
  /// @dev `customParams` is `abi.encode(address seller, address buyer, uint8 levels, uint256 minPrice,
  /// uint256 stepPrice, string title)`. The buyer may be the zero address: the seat is then open and
  /// the first valid buyer offer of a party other than the seller takes it (`publishInput`). Level `i`
  /// has the price `minPrice + i * stepPrice`. Interfold calls this inside `request`, and the requester
  /// is already set.
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
    Terms memory terms;
    (terms.seller, terms.buyer, terms.levels, terms.minPrice, terms.stepPrice, terms.title) = abi.decode(
      customParams,
      (address, address, uint8, uint256, uint256, string)
    );
    // The buyer may be the zero address: the seat is open until a buyer offer takes it.
    if (terms.seller == address(0) || terms.seller == terms.buyer) revert InvalidParties();
    if (terms.levels < MIN_LEVELS || terms.levels > MAX_LEVELS) revert InvalidLevels(terms.levels);
    // Each term is below 2^128, so the highest price is below 2^128 * 16 and cannot overflow here.
    if (
      terms.stepPrice == 0 ||
      terms.minPrice >= PRICE_LIMIT ||
      terms.stepPrice >= PRICE_LIMIT ||
      terms.minPrice + terms.stepPrice * (terms.levels - 1) >= PRICE_LIMIT
    ) revert InvalidPrices();
    terms.creator = interfold.getE3(e3Id).requester;
    negotiation[e3Id] = terms;
    inputs[e3Id]._init(TREE_DEPTH);
    inputs[e3Id]._insert(configLeaf());
    emit NegotiationCreated(e3Id, terms.creator, terms.seller, terms.buyer, terms.levels, terms.minPrice, terms.stepPrice, terms.title);
    return ENCRYPTION_SCHEME_ID;
  }

  /// @notice The outcome of the negotiation of `e3Id`. Without `settle`, `settled` is `false`.
  /// @return settled Whether `settle` ran.
  /// @return matched Whether the parties agreed on a price.
  /// @return step The agreed level, 0 if there is no match.
  /// @return price The agreed price, 0 if there is no match.
  function outcome(uint256 e3Id) external view returns (bool settled, bool matched, uint8 step, uint256 price) {
    Outcome storage o = _outcome[e3Id];
    return (o.settled, o.matched, o.step, o.price);
  }

  function _terms(uint256 e3Id) private view returns (Terms storage terms) {
    terms = negotiation[e3Id];
    if (terms.creator == address(0)) revert E3DoesNotExist();
  }

  // ---------------------------------------------------------------------------------------------
  // Offers
  // ---------------------------------------------------------------------------------------------

  /// @notice Leaf 0 of a negotiation: the configuration input, hashed into the field. The program
  /// reads it as input 0, so the compute proof binds the program to this contract through the input root.
  function configLeaf() public pure returns (uint256) {
    return uint256(keccak256(CONFIG_DOMAIN)) % SNARK_SCALAR_FIELD;
  }

  /// @notice The leaf of one ciphertext of an offer. The program computes the same value from the
  /// published bytes and the 25 bytes of metadata `party || uint40(role * 256 + index)`.
  /// @param ciphertextHash `keccak256` of the ciphertext bytes.
  /// @param commitment The SAFE commitment of the ciphertext, which the offer proof binds.
  /// @param party The seller or the buyer.
  /// @param role 0 for the seller, 1 for the buyer.
  /// @param index The position of the ciphertext in the offer, 0 to 2.
  function inputLeaf(bytes32 ciphertextHash, bytes32 commitment, address party, uint8 role, uint8 index) public pure returns (uint256) {
    return uint256(sha256(abi.encodePacked(ciphertextHash, commitment, party, uint40(uint256(role) * 256 + index)))) % SNARK_SCALAR_FIELD;
  }

  /// @notice The EIP-712 digest that a party signs to let a relayer send its offer.
  /// @param inputsHash `keccak256(abi.encode(commitments, keccak256(ciphertexts[0]), keccak256(ciphertexts[1]), keccak256(ciphertexts[2])))`.
  function offerDigest(uint256 e3Id, address party, bytes32 inputsHash) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(OFFER_TYPEHASH, e3Id, party, inputsHash)));
  }

  /// @notice Send the offer of the seller or of the buyer. Each party sends one offer. If the buyer seat
  /// is open, the first valid offer of a party that is not the seller takes the seat and fixes the buyer.
  /// @param data `abi.encode(address party, bytes[] ciphertexts, bytes32[] commitments, bytes proof,
  /// bytes signature)`. With an empty `signature` the sender must be `party`. Otherwise `signature` is
  /// the EIP-712 signature of `party` (`offerDigest`), and anyone may send.
  function publishInput(uint256 e3Id, bytes memory data) external override {
    Terms storage terms = _terms(e3Id);
    E3 memory e3 = interfold.getE3(e3Id);
    if (block.timestamp > e3.inputWindow[1]) revert InputDeadlineReached();
    OfferInput memory offer;
    (offer.party, offer.ciphertexts, offer.commitments, offer.proof, offer.signature) = abi.decode(
      data,
      (address, bytes[], bytes32[], bytes, bytes)
    );
    uint8 role;
    // An open seat (the buyer is the zero address) goes to the first sender that is not the seller.
    // The zero address is never a party, so it cannot match the zero buyer of an open seat.
    if (offer.party == address(0)) revert NotAParty(offer.party);
    if (offer.party == terms.seller) role = SELLER;
    else if (offer.party == terms.buyer || terms.buyer == address(0)) role = BUYER;
    else revert NotAParty(offer.party);
    if (offer.ciphertexts.length != OFFER_CIPHERTEXTS || offer.commitments.length != OFFER_CIPHERTEXTS) revert InvalidOfferShape();
    if (offerSubmitted[e3Id][role]) revert AlreadySubmitted(offer.party, role);

    bytes32[] memory hashes = new bytes32[](OFFER_CIPHERTEXTS);
    for (uint256 r = 0; r < OFFER_CIPHERTEXTS; r++) {
      if (offer.ciphertexts[r].length == 0) revert EmptyInputData();
      hashes[r] = keccak256(offer.ciphertexts[r]);
    }
    _checkSender(e3Id, offer, hashes);
    _verifyOfferProof(offer, role, terms.levels, e3.committeePublicKey);

    // An open seat is taken here, after every check passed: only a valid buyer offer takes it. The
    // program drops an offer whose ciphertexts do not open their commitments, but the seat stays taken.
    if (role == BUYER && terms.buyer == address(0)) {
      terms.buyer = offer.party;
      emit BuyerJoined(e3Id, offer.party);
    }
    offerSubmitted[e3Id][role] = true;
    uint256 firstLeaf = inputs[e3Id].numberOfLeaves;
    for (uint256 r = 0; r < OFFER_CIPHERTEXTS; r++) {
      inputs[e3Id]._insert(inputLeaf(hashes[r], offer.commitments[r], offer.party, role, uint8(r)));
    }
    emit OfferSubmitted(e3Id, offer.party, role, firstLeaf, offer.ciphertexts, offer.commitments);
  }

  /// @dev A direct offer comes from its party. A relayed offer carries the party's signature over the
  /// hash of the exact commitments and ciphertexts, so a relayer cannot swap bytes.
  function _checkSender(uint256 e3Id, OfferInput memory offer, bytes32[] memory hashes) private view {
    if (offer.signature.length == 0) {
      if (offer.party != msg.sender) revert SenderNotParty(msg.sender, offer.party);
      return;
    }
    bytes32 inputsHash = keccak256(abi.encode(offer.commitments, hashes[0], hashes[1], hashes[2]));
    if (!SignatureChecker.isValidSignatureNow(offer.party, offerDigest(e3Id, offer.party, inputsHash), offer.signature)) {
      revert InvalidSignature(offer.party);
    }
  }

  /// @dev Public inputs of `negotiation_offer`: `ct_commitments[0..2], party, role, levels,
  /// pk_commitment, vk_anchor`. See `circuits/PUBLIC_INPUTS.md`.
  function _verifyOfferProof(OfferInput memory offer, uint8 role, uint8 levels, bytes32 committeePublicKey) private view {
    bytes32[] memory publicInputs = new bytes32[](8);
    publicInputs[0] = offer.commitments[0];
    publicInputs[1] = offer.commitments[1];
    publicInputs[2] = offer.commitments[2];
    publicInputs[3] = bytes32(uint256(uint160(offer.party)));
    publicInputs[4] = bytes32(uint256(role));
    publicInputs[5] = bytes32(uint256(levels));
    publicInputs[6] = committeePublicKey;
    publicInputs[7] = vkAnchor;
    if (!offerVerifier.verify(offer.proof, publicInputs)) revert InvalidOfferProof();
  }

  // ---------------------------------------------------------------------------------------------
  // Settlement
  // ---------------------------------------------------------------------------------------------

  /// @notice Read the outcome from the published plaintext and store it. Anyone may call it, once.
  /// It reverts with `InvalidOutput` if the plaintext is not a one-hot level vector or the zero vector.
  function settle(uint256 e3Id) external {
    Terms storage terms = _terms(e3Id);
    Outcome storage o = _outcome[e3Id];
    if (o.settled) revert AlreadySettled();
    bytes memory plaintext = interfold.getE3(e3Id).plaintextOutput;
    if (plaintext.length == 0) revert OutputNotPublished();
    (bool matched, uint8 step) = NegotiationOutput.decode(plaintext, terms.levels);
    uint256 price = matched ? terms.minPrice + uint256(step) * terms.stepPrice : 0;
    o.settled = true;
    o.matched = matched;
    o.step = step;
    o.price = price;
    emit Settled(e3Id, matched, step, price);
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
