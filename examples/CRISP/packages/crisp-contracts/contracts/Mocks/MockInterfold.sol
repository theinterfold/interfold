// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";
import { IDecryptionVerifier } from "@interfold/contracts/contracts/interfaces/IDecryptionVerifier.sol";
import { IPkVerifier } from "@interfold/contracts/contracts/interfaces/IPkVerifier.sol";
import { ICiphernodeRegistry } from "@interfold/contracts/contracts/interfaces/ICiphernodeRegistry.sol";

contract MockInterfold {
  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  bytes public plaintextOutput;
  bytes32 public committeePublicKey;
  uint256[2] public mockInputWindow;
  uint256 public mockRequestBlock;
  uint256 public mockRandomnessRequestTimeout;
  uint256 public mockSortitionSubmissionWindow;
  uint256 public mockDkgWindow;

  uint256 public nextE3Id;

  mapping(uint256 => E3) public e3s;
  mapping(IE3Program => bool) public e3Programs;

  function registerE3Program(IE3Program program) external {
    e3Programs[program] = true;
  }

  function request(address program) external {
    _request(program, 2);
  }

  /// @notice Request an E3 with a caller-supplied option count, so tests can
  /// cover tallies with more than two options.
  function requestWithOptions(address program, uint256 numOptions) external {
    _request(program, numOptions);
  }

  /// @notice Request an E3 with caller-supplied program params.
  /// @dev `_request` hardcodes a TOKEN-census round. `CensusMode.ONCHAIN` needs a token, a credit
  /// mode and a census mode that only the caller knows, and the snapshot is taken during
  /// `validate`, so the params have to reach it here rather than being patched afterwards.
  function requestWithParams(address program, uint256 numOptions, bytes memory params) external {
    mockRequestBlock = block.timestamp;
    e3s[nextE3Id] = E3({
      seed: 0,
      committeeSize: IInterfold.CommitteeSize.Minimum,
      requestBlock: mockRequestBlock,
      inputWindow: [uint256(0), uint256(0)],
      encryptionSchemeId: ENCRYPTION_SCHEME_ID,
      e3Program: IE3Program(address(0)),
      paramSet: 0, // Insecure512
      customParams: params,
      decryptionVerifier: IDecryptionVerifier(address(0)),
      pkVerifier: IPkVerifier(address(0)),
      committeePublicKey: committeePublicKey,
      ciphertextOutput: bytes32(0),
      plaintextOutput: plaintextOutput,
      requester: address(0),
      ciphertextCommitment: bytes32(0)
    });

    IE3Program(program).validate(nextE3Id, 0, bytes(""), bytes(""), params);

    nextE3Id++;
    numOptions; // silence unused-parameter warning; the count travels inside `params`
  }

  function _request(address program, uint256 numOptions) internal {
    mockRequestBlock = block.timestamp;
    e3s[nextE3Id] = E3({
      seed: 0,
      committeeSize: IInterfold.CommitteeSize.Minimum,
      requestBlock: mockRequestBlock,
      inputWindow: [uint256(0), uint256(0)],
      encryptionSchemeId: ENCRYPTION_SCHEME_ID,
      e3Program: IE3Program(address(0)),
      paramSet: 0, // Insecure512
      customParams: abi.encode(address(0), nextE3Id, numOptions, 0, 0, 0, 0),
      decryptionVerifier: IDecryptionVerifier(address(0)),
      pkVerifier: IPkVerifier(address(0)),
      committeePublicKey: committeePublicKey,
      ciphertextOutput: bytes32(0),
      plaintextOutput: plaintextOutput,
      requester: address(0),
      ciphertextCommitment: bytes32(0)
    });

    IE3Program(program).validate(nextE3Id, 0, bytes(""), bytes(""), abi.encode(address(0), nextE3Id, numOptions, 0, 0, 0, 0));

    nextE3Id++;
  }

  function setPlaintextOutput(bytes memory plaintext) external {
    plaintextOutput = plaintext;
  }

  function setCommitteePublicKey(bytes32 publicKeyHash) external {
    committeePublicKey = publicKeyHash;
  }

  function setInputWindow(uint256 start, uint256 end) external {
    mockInputWindow = [start, end];
  }

  function setCommitteeSetupWindows(uint256 randomness, uint256 sortition, uint256 dkg) external {
    mockRandomnessRequestTimeout = randomness;
    mockSortitionSubmissionWindow = sortition;
    mockDkgWindow = dkg;
  }

  function getE3Stage(uint256) external view returns (IInterfold.E3Stage) {
    return IInterfold.E3Stage.KeyPublished;
  }

  function getDeadlines(uint256) external view returns (IInterfold.E3Deadlines memory) {
    uint256 inputEnd = mockInputWindow[1] == 0 ? block.timestamp + 100 : mockInputWindow[1];
    return IInterfold.E3Deadlines({ dkgDeadline: 0, computeDeadline: inputEnd + 100, decryptionDeadline: inputEnd + 200 });
  }

  function getE3TimeoutConfig(uint256) external view returns (IInterfold.E3TimeoutConfig memory) {
    return IInterfold.E3TimeoutConfig({ dkgWindow: mockDkgWindow, computeWindow: 100, decryptionWindow: 100 });
  }

  function ciphernodeRegistry() external view returns (ICiphernodeRegistry) {
    return ICiphernodeRegistry(address(this));
  }

  function randomnessRequestTimeout() external view returns (uint256) {
    return mockRandomnessRequestTimeout;
  }

  function sortitionSubmissionWindow() external view returns (uint256) {
    return mockSortitionSubmissionWindow;
  }

  function getE3(uint256) external view returns (E3 memory) {
    uint256[2] memory inputWindow = mockInputWindow[1] == 0 ? [uint256(0), block.timestamp + 100] : mockInputWindow;
    return
      E3({
        seed: 0,
        committeeSize: IInterfold.CommitteeSize.Minimum,
        requestBlock: mockRequestBlock,
        inputWindow: inputWindow,
        encryptionSchemeId: ENCRYPTION_SCHEME_ID,
        e3Program: IE3Program(address(0)),
        paramSet: 0, // Insecure512
        customParams: abi.encode(address(0), 0, 2, 0, 0, 0, 0),
        decryptionVerifier: IDecryptionVerifier(address(0)),
        pkVerifier: IPkVerifier(address(0)),
        committeePublicKey: committeePublicKey,
        ciphertextOutput: bytes32(0),
        plaintextOutput: plaintextOutput,
        requester: address(0),
        ciphertextCommitment: bytes32(0)
      });
  }
}
