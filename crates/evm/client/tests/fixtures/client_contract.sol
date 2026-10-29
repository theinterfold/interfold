// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity >=0.8.24;

contract ClientContract {
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

  struct E3RequestParams {
    uint8 committeeSize;
    uint256[2] inputWindow;
    address e3Program;
    uint8 paramSet;
    bytes computeProviderParams;
    bytes customParams;
    address expectedFeeToken;
    bytes32 expectedCryptoConfigId;
    uint256 maxFee;
  }

  event E3Requested(uint256 e3Id, E3 e3, bytes32 indexed cryptoConfigId);

  E3 private requested;

  function feeToken() external pure returns (address) {
    return address(0);
  }

  function getE3Quote(E3RequestParams calldata) external pure returns (uint256) {
    return 0;
  }

  function request(E3RequestParams calldata params) external returns (uint256 e3Id, E3 memory e3) {
    e3Id = 41;
    e3.committeeSize = params.committeeSize;
    e3.e3Program = params.e3Program;
    e3.paramSet = params.paramSet;
    e3.customParams = params.customParams;
    e3.inputWindow = params.inputWindow;
    e3.requester = msg.sender;
    requested = e3;
    emit E3Requested(e3Id, e3, params.expectedCryptoConfigId);
  }

  function getE3(uint256) external view returns (E3 memory) {
    return requested;
  }

  function getE3Stage(uint256) external pure returns (uint8) {
    return 255;
  }

  function getFailureReason(uint256) external pure returns (uint8) {
    return 13;
  }

  function registerE3Program(address) external {}
}
