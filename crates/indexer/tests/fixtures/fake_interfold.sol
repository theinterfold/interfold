// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity >=0.4.24;

contract FakeInterfold {
  event InputPublished(uint256 indexed e3Id, bytes data, uint256 inputHash, uint256 index);
  event CiphertextOutputPublished(uint256 indexed e3Id, bytes ciphertextOutput);
  event PlaintextOutputPublished(uint256 indexed e3Id, bytes plaintextOutput, bytes proof);
  event CommitteePublished(uint256 indexed e3Id, address[] nodes, bytes publicKey, bytes32 pkCommitment, bytes proof);

  mapping(uint8 => bytes) public paramSetRegistry;

  // Emit InputPublished event with passed test data
  function emitInputPublished(uint256 e3Id, bytes memory data, uint256 inputHash, uint256 index) public {
    emit InputPublished(e3Id, data, inputHash, index);
  }

  // Emit CiphertextOutputPublished event with passed test data
  function emitCiphertextOutputPublished(uint256 e3Id, bytes memory ciphertextOutput) public {
    emit CiphertextOutputPublished(e3Id, ciphertextOutput);
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

  function getE3(uint256 _e3Id) external view returns (E3 memory e3) {
    e3 = E3({
      seed: 123456789012,
      committeeSize: CommitteeSize.Minimum,
      requestBlock: 18750000,
      inputWindow: [uint256(18750100), uint256(18750200)],
      encryptionSchemeId: bytes32(keccak256("AES-256-GCM")),
      e3Program: 0x7F3E4df648B8Cb96C1D343be976b91B97CaD5c21,
      decryptionVerifier: 0x4B0D8c2E5f7a6c832f8b16d3aB0e7F5d9E9B24b1,
      pkVerifier: 0x5C1e9D3f8A7B6c932F9C27e4Ab1F8F6e0F0C35c2,
      paramSet: 0,
      customParams: abi.encode("custom_params"),
      committeePublicKey: bytes32(keccak256("committee_public_key")),
      ciphertextOutput: bytes32(keccak256("encrypted_data")),
      plaintextOutput: abi.encode("decrypted_result"),
      requester: 0xdead000000000000000000000000000000000001
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
}
