// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity ^0.8.27;

/// The `Interfold` and `CRISPProgram` state of one input, as the availability service reads and
/// writes it.
///
/// The service tests deploy it from the service key, so that key is the availability signer. The
/// tests hold its creation code from `solc --optimize --bin mock_crisp_availability.sol`.
contract MockCrispAvailability {
  struct E3 {
    uint256 seed;
    uint8 committeeSize;
    uint256 requestBlock;
    uint256[2] inputWindow;
    bytes32 encryptionSchemeId;
    address e3Program;
    uint8 paramSet;
    bytes customParams;
    address decryptionVerifier;
    address pkVerifier;
    bytes32 committeePublicKey;
    bytes32 ciphertextOutput;
    bytes plaintextOutput;
    address requester;
    bytes32 ciphertextCommitment;
  }

  uint64 public constant INPUT_AVAILABILITY_ATTESTATION_TTL = 10 minutes;
  address public immutable inputAvailabilitySigner = msg.sender;
  bytes32 public immutable cryptoConfigId;
  bool public committed;
  bool public published;
  uint256 public commitmentDeadline;
  /// A test that does not set the compute deadline never reaches it.
  uint256 public computeDeadline = type(uint64).max;
  /// Every `publishInput` and `finalizeInput` transaction.
  uint256 public sends;

  constructor(bytes32 configId) {
    cryptoConfigId = configId;
  }

  function set(bool isCommitted, bool isPublished, uint256 deadline) external {
    committed = isCommitted;
    published = isPublished;
    commitmentDeadline = deadline;
  }

  function setComputeDeadline(uint256 deadline) external {
    computeDeadline = deadline;
  }

  /// An insecure round.
  function getE3(uint256) external pure returns (E3 memory e3) {}

  function getDeadlines(uint256) external view returns (uint256, uint256, uint256) {
    return (0, computeDeadline, 0);
  }

  function e3CryptoConfigIds(uint256) external view returns (bytes32) {
    return cryptoConfigId;
  }

  function inputCommitmentDeadline(uint256) external view returns (uint256) {
    return commitmentDeadline;
  }

  function isInputCommitted(uint256, bytes32, bytes32, address, uint40) external view returns (bool) {
    return committed;
  }

  function isInputPublished(uint256, bytes32, bytes32, address, uint40) external view returns (bool) {
    return published;
  }

  /// Refuses a committed input, as `CRISPProgram` does for the existing leaf.
  function validateInputProof(uint256, bytes calldata, address, bytes32, bytes32, uint40) external view returns (bool) {
    require(!committed, "InputAlreadyPublished");
    return true;
  }

  function inputId(uint256, bytes32, bytes32, address, uint40) external pure returns (bytes32) {
    return bytes32(0);
  }

  function inputAvailabilityDigest(uint256, bytes32, uint64 expiresAt) external pure returns (bytes32) {
    return keccak256(abi.encode(expiresAt));
  }

  /// Accepts a repeat, unlike `CRISPProgram`, so that `sends` counts a second paid transaction.
  function publishInput(uint256, bytes calldata) external {
    committed = true;
    sends++;
  }

  function finalizeInput(uint256, address, bytes32, bytes32, uint40, bytes calldata) external {
    published = true;
    sends++;
  }
}
