// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity >=0.4.24;

contract FakeInterfold {
  event InputPublished(uint256 indexed e3Id, bytes data, uint256 inputHash, uint256 index);
  event CiphertextOutputPublished(uint256 indexed e3Id, bytes ciphertextOutput, bytes32 ciphertextCommitment);
  event PlaintextOutputPublished(uint256 indexed e3Id, bytes plaintextOutput, bytes proof);
  event CommitteePublished(uint256 indexed e3Id, address[] nodes, bytes publicKey, bytes32 pkCommitment, bytes proof);
  event CommitteePublicKeyChunkPublished(
    uint256 indexed e3Id,
    address indexed publisher,
    bytes32 indexed candidateHash,
    address[] nodes,
    bytes32 pkCommitment,
    uint16 chunkIndex,
    uint16 chunkCount,
    uint32 totalLength,
    bytes chunk
  );

  mapping(uint8 => bytes) public paramSetRegistry;
  mapping(uint256 => bytes32) private cryptoConfigOverrides;
  mapping(uint256 => bytes32) private encryptionSchemeOverrides;
  mapping(uint256 => uint8) private paramSetOverrides;

  function setCryptoConfigId(uint256 e3Id, bytes32 configId) external {
    cryptoConfigOverrides[e3Id] = configId;
  }

  function setRequestCrypto(uint256 e3Id, bytes32 schemeId, uint8 paramSet, bytes32 configId) external {
    encryptionSchemeOverrides[e3Id] = schemeId;
    paramSetOverrides[e3Id] = paramSet;
    cryptoConfigOverrides[e3Id] = configId;
  }

  function e3CryptoConfigIds(uint256 e3Id) external view returns (bytes32) {
    if (cryptoConfigOverrides[e3Id] != bytes32(0)) return cryptoConfigOverrides[e3Id];
    return 0x92c8b373eb72cc3600a5a818cf8599db16e618ee3ece2dadd14f8608c1a43ac9;
  }

  // Emit InputPublished event with passed test data
  function emitInputPublished(uint256 e3Id, bytes memory data, uint256 inputHash, uint256 index) public {
    emit InputPublished(e3Id, data, inputHash, index);
  }

  // Emit CiphertextOutputPublished event with passed test data
  function emitCiphertextOutputPublished(uint256 e3Id, bytes memory ciphertextOutput, bytes32 ciphertextCommitment) public {
    emit CiphertextOutputPublished(e3Id, ciphertextOutput, ciphertextCommitment);
  }

  // Emit PlaintextOutputPublished event with passed test data
  function emitPlaintextOutputPublished(uint256 e3Id, bytes memory plaintextOutput, bytes memory proof) public {
    emit PlaintextOutputPublished(e3Id, plaintextOutput, proof);
  }

  // Emit CommitteePublished event with passed test data
  function emitCommitteePublished(uint256 e3Id, bytes memory publicKey, bytes32 pkCommitment, bytes memory proof) public {
    address[] memory nodes = new address[](1);
    emit CommitteePublished(e3Id, nodes, publicKey, pkCommitment, proof);
  }

  function emitPublicKeyChunk(
    uint256 e3Id,
    address publisher,
    bytes32 candidateHash,
    bytes32 pkCommitment,
    uint16 chunkIndex,
    uint16 chunkCount,
    uint32 totalLength,
    bytes calldata chunk
  ) external {
    address[] memory nodes = new address[](1);
    nodes[0] = address(1);
    emit CommitteePublicKeyChunkPublished(e3Id, publisher, candidateHash, nodes, pkCommitment, chunkIndex, chunkCount, totalLength, chunk);
  }

  function getE3(uint256 _e3Id) external view returns (E3 memory e3) {
    e3 = E3({
      seed: 123456789012,
      committeeSize: CommitteeSize.Minimum,
      requestBlock: 18750000,
      inputWindow: [uint256(18750100), uint256(18750200)],
      encryptionSchemeId: encryptionSchemeOverrides[_e3Id] == bytes32(0) ? keccak256("AES-256-GCM") : encryptionSchemeOverrides[_e3Id],
      e3Program: 0x7F3E4df648B8Cb96C1D343be976b91B97CaD5c21,
      decryptionVerifier: 0x4B0D8c2E5f7a6c832f8b16d3aB0e7F5d9E9B24b1,
      pkVerifier: 0x5C1e9D3f8A7B6c932F9C27e4Ab1F8F6e0F0C35c2,
      paramSet: paramSetOverrides[_e3Id],
      customParams: abi.encode("custom_params"),
      committeePublicKey: bytes32(keccak256("committee_public_key")),
      ciphertextOutput: bytes32(keccak256("encrypted_data")),
      plaintextOutput: abi.encode("decrypted_result"),
      requester: 0xdead000000000000000000000000000000000001,
      ciphertextCommitment: bytes32(keccak256("ciphertext_commitment"))
    });
  }
}

enum CommitteeSize {
  Minimum,
  Micro,
  Small
}

struct E3 {
  uint256 seed;
  CommitteeSize committeeSize;
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
