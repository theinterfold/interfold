// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IRiscZeroVerifier } from "risc0/IRiscZeroVerifier.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { HonkVerifier } from "./CRISPVerifier.sol";

contract CRISPProgram is IE3Program, Ownable {
  using InternalLazyIMT for LazyIMTData;

  /// @notice Enum to represent credit modes
  enum CreditMode {
    /// @notice Everyone has constant credits
    CONSTANT,
    /// @notice Credits are custom (can be based on token balance, etc)
    CUSTOM
  }

  /// @notice Struct to store all data related to a voting round
  struct RoundData {
    uint256 merkleRoot;
    bytes32 paramsHash;
    mapping(address slot => uint40 index) voteSlots;
    LazyIMTData votes;
    uint256 numOptions;
    CreditMode creditMode;
  }

  // Constants
  /// @notice Encryption scheme ID used for the CRISP program.
  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  /// @notice The depth of the input Merkle tree.
  uint8 public constant TREE_DEPTH = 20;
  /// @notice Maximum number of bits allocated for vote counts in the plaintext output per option.
  uint256 constant MAX_VOTE_BITS = 50;
  // State variables
  IInterfold public interfold;
  IRiscZeroVerifier public risc0Verifier;
  bytes32 public imageId;
  HonkVerifier private immutable honkVerifier;

  // Mappings
  mapping(uint256 e3Id => RoundData) e3Data;

  // Errors
  error CallerNotAuthorized();
  error E3AlreadyInitialized();
  error InterfoldAddressZero();
  error Risc0VerifierAddressZero();
  error InvalidHonkVerifier();
  error EmptyInputData();
  error InvalidNoirProof();
  error InvalidMerkleRoot();
  error MerkleRootAlreadySet();
  error InvalidTallyLength();
  error SlotIsEmpty();
  error MerkleRootNotSet();
  error InvalidNumOptions();
  error InputDeadlinePassed(uint256 e3Id, uint256 deadline);
  error KeyNotPublished(uint256 e3Id);
  error E3NotAcceptingInputs(uint256 e3Id);

  // Events
  event InputPublished(uint256 indexed e3Id, bytes encryptedVote, uint256 index);

  /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
  /// @param _interfold The interfold address
  /// @param _risc0Verifier The RISC Zero verifier address
  /// @param _honkVerifier The honk verifier address
  /// @param _imageId The image ID for the guest program
  constructor(IInterfold _interfold, IRiscZeroVerifier _risc0Verifier, HonkVerifier _honkVerifier, bytes32 _imageId) Ownable(msg.sender) {
    if (address(_interfold) == address(0)) revert InterfoldAddressZero();
    if (address(_risc0Verifier) == address(0)) revert Risc0VerifierAddressZero();
    if (address(_honkVerifier) == address(0)) revert InvalidHonkVerifier();

    interfold = _interfold;
    risc0Verifier = _risc0Verifier;
    honkVerifier = _honkVerifier;
    imageId = _imageId;
  }

  /// @notice Sets the Merkle root for an E3 program. Can only be set once.
  /// @param _e3Id The E3 program ID
  /// @param _root The Merkle root to set.
  function setMerkleRoot(uint256 _e3Id, uint256 _root) external onlyOwner {
    if (_root == 0) revert InvalidMerkleRoot();
    if (e3Data[_e3Id].merkleRoot != 0) revert MerkleRootAlreadySet();

    e3Data[_e3Id].merkleRoot = _root;
  }

  /// @notice Set the Image ID for the guest program
  /// @param _imageId The new image ID.
  function setImageId(bytes32 _imageId) external onlyOwner {
    imageId = _imageId;
  }

  /// @notice Set the RISC Zero verifier.
  /// @param _risc0Verifier The new RISC Zero verifier address
  function setRisc0Verifier(IRiscZeroVerifier _risc0Verifier) external onlyOwner {
    if (address(_risc0Verifier) == address(0)) revert Risc0VerifierAddressZero();
    risc0Verifier = _risc0Verifier;
  }

  /// @notice Get the params hash for an E3 program
  /// @param e3Id The E3 program ID
  /// @return The params hash
  function getParamsHash(uint256 e3Id) public view returns (bytes32) {
    return e3Data[e3Id].paramsHash;
  }

  /// @inheritdoc IE3Program
  function validate(
    uint256 e3Id,
    uint256,
    bytes calldata e3ProgramParams,
    bytes calldata,
    bytes calldata customParams
  ) external returns (bytes32) {
    if (msg.sender != address(interfold) && msg.sender != owner()) revert CallerNotAuthorized();
    if (e3Data[e3Id].paramsHash != bytes32(0)) revert E3AlreadyInitialized();

    // decode custom params to get the number of options
    (, , uint256 numOptions, CreditMode creditMode, ) = abi.decode(customParams, (address, uint256, uint256, CreditMode, uint256));
    if (numOptions < 2) revert InvalidNumOptions();

    // we need to know the number of options for decoding the tally
    e3Data[e3Id].numOptions = numOptions;
    // we want to save the credit mode so it can be verified on chain by everyone
    e3Data[e3Id].creditMode = creditMode;

    e3Data[e3Id].paramsHash = keccak256(e3ProgramParams);

    // Initialize the votes Merkle tree for this E3 ID.
    e3Data[e3Id].votes._init(TREE_DEPTH);

    return ENCRYPTION_SCHEME_ID;
  }

  /// @inheritdoc IE3Program
  function publishInput(uint256 e3Id, bytes memory data) external {
    E3 memory e3 = interfold.getE3(e3Id);

    // check that we are in the correct stage
    IInterfold.E3Stage stage = interfold.getE3Stage(e3Id);
    if (stage != IInterfold.E3Stage.KeyPublished) {
      revert KeyNotPublished(e3Id);
    }

    // check that we are not past the input deadline
    if (block.timestamp > e3.inputWindow[1]) {
      revert InputDeadlinePassed(e3Id, e3.inputWindow[1]);
    }

    // check that we are within the input window
    if (block.timestamp < e3.inputWindow[0]) {
      revert E3NotAcceptingInputs(e3Id);
    }

    // We need to ensure that the CRISP admin set the merkle root of the census.
    if (e3Data[e3Id].merkleRoot == 0) revert MerkleRootNotSet();

    if (data.length == 0) revert EmptyInputData();

    (bytes memory noirProof, address slotAddress, bytes32 encryptedVoteCommitment, bytes memory encryptedVote) = abi.decode(
      data,
      (bytes, address, bytes32, bytes)
    );

    (uint40 voteIndex, bytes32 previousEncryptedVoteCommitment) = _processVote(e3Id, slotAddress, encryptedVoteCommitment);

    // Set the public inputs for the proof. Order must match Noir circuit.
    bytes32[] memory noirPublicInputs = new bytes32[](7);
    noirPublicInputs[0] = previousEncryptedVoteCommitment;
    noirPublicInputs[1] = bytes32(e3Data[e3Id].merkleRoot);
    noirPublicInputs[2] = bytes32(uint256(uint160(slotAddress)));
    noirPublicInputs[3] = bytes32(uint256(previousEncryptedVoteCommitment == bytes32(0) ? 1 : 0));
    noirPublicInputs[4] = bytes32(e3Data[e3Id].numOptions);
    noirPublicInputs[5] = encryptedVoteCommitment;
    noirPublicInputs[6] = e3.committeePublicKey;

    // Check if the ciphertext was encrypted correctly
    if (!honkVerifier.verify(noirProof, noirPublicInputs)) {
      revert InvalidNoirProof();
    }

    emit InputPublished(e3Id, encryptedVote, voteIndex);
  }

  /// @notice Decode the tally from the plaintext output
  /// @param e3Id The E3 program ID
  /// @return votes - an array of vote counts for each option
  function decodeTally(uint256 e3Id) public view returns (uint256[] memory votes) {
    E3 memory e3 = interfold.getE3(e3Id);

    uint256 numOptions = e3Data[e3Id].numOptions;

    // If num optionsis not configured, return empty array to avoid decoding errors.
    // Users might be calling this function too early and there's no
    if (numOptions == 0) {
      return new uint256[](0);
    }

    uint64[] memory tally = _decodeBytesToUint64Array(e3.plaintextOutput);

    uint256 segmentSize = tally.length / numOptions;
    uint256 effectiveSize = segmentSize > MAX_VOTE_BITS ? MAX_VOTE_BITS : segmentSize;

    votes = new uint256[](numOptions);

    for (uint256 optIdx = 0; optIdx < numOptions; optIdx++) {
      uint256 segmentStart = optIdx * segmentSize;
      // Read only the last effectiveSize bits (where the value is, MSB first)
      uint256 readStart = segmentStart + segmentSize - effectiveSize;
      uint256 value = 0;

      for (uint256 i = 0; i < effectiveSize; i++) {
        uint256 weight = 2 ** (effectiveSize - 1 - i);
        value += uint256(tally[readStart + i]) * weight;
      }

      votes[optIdx] = value;
    }

    return votes;
  }

  /// @notice Get the slot index for a given E3 ID and slot address
  /// @param e3Id The E3 program ID
  /// @param slotAddress The slot address
  /// @return The slot index, or -1 if the slot is empty
  function getSlotIndex(uint256 e3Id, address slotAddress) external view returns (int40) {
    uint40 storedIndexPlusOne = e3Data[e3Id].voteSlots[slotAddress];
    return int40(storedIndexPlusOne) - 1;
  }

  /// @inheritdoc IE3Program
  function verify(uint256 e3Id, bytes32 ciphertextOutputHash, bytes memory proof) external view override returns (bool) {
    bytes32 paramsHash = getParamsHash(e3Id);

    bytes32 inputRoot = bytes32(e3Data[e3Id].votes._root(TREE_DEPTH));
    bytes memory journal = new bytes(396); // (32 + 1) * 4 * 3

    _encodeLengthPrefixAndHash(journal, 0, ciphertextOutputHash);
    _encodeLengthPrefixAndHash(journal, 132, paramsHash);
    _encodeLengthPrefixAndHash(journal, 264, inputRoot);

    risc0Verifier.verify(proof, imageId, sha256(journal));
    return true;
  }

  /// @notice Process a vote: insert or update in the merkle tree depending
  /// on whether it's the first vote or an override.
  function _processVote(
    uint256 e3Id,
    address slotAddress,
    bytes32 encryptedVoteCommitment
  ) internal returns (uint40 voteIndex, bytes32 previousEncryptedVoteCommitment) {
    uint40 storedIndexPlusOne = e3Data[e3Id].voteSlots[slotAddress];

    // we treat the index 0 as not voted yet
    // any valid index will be index + 1
    if (storedIndexPlusOne == 0) {
      // FIRST VOTE
      previousEncryptedVoteCommitment = bytes32(0);
      voteIndex = e3Data[e3Id].votes.numberOfLeaves;
      e3Data[e3Id].voteSlots[slotAddress] = voteIndex + 1;
      e3Data[e3Id].votes._insert(uint256(encryptedVoteCommitment));
    } else {
      // RE-VOTE
      voteIndex = storedIndexPlusOne - 1;
      previousEncryptedVoteCommitment = bytes32(e3Data[e3Id].votes.elements[voteIndex]);
      e3Data[e3Id].votes._update(uint256(encryptedVoteCommitment), voteIndex);
    }
  }

  /// @notice Encode length prefix and hash
  /// @param journal The journal to encode into
  /// @param startIndex The start index in the journal
  /// @param hashVal The hash value to encode
  function _encodeLengthPrefixAndHash(bytes memory journal, uint256 startIndex, bytes32 hashVal) internal pure {
    journal[startIndex] = 0x20;
    startIndex += 4;

    for (uint256 i = 0; i < 32; i++) {
      journal[startIndex + i * 4] = hashVal[i];
    }
  }

  /// @notice Decode bytes to uint64 array
  /// @param data The bytes to decode (must be multiple of 8)
  /// @return result Array of uint64 values
  function _decodeBytesToUint64Array(bytes memory data) internal pure returns (uint64[] memory result) {
    if (data.length % 8 != 0) {
      revert InvalidTallyLength();
    }

    uint256 arrayLength = data.length / 8;
    result = new uint64[](arrayLength);

    for (uint256 i = 0; i < arrayLength; i++) {
      uint256 offset = i * 8;
      uint64 value = 0;

      // Read 8 bytes in little-endian order
      for (uint64 j = 0; j < 8; j++) {
        value |= uint64(uint8(data[offset + j])) << (j * 8);
      }

      result[i] = value;
    }

    return result;
  }
}
