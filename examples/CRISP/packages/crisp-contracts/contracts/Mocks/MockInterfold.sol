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

contract MockInterfold {
  bytes public plaintextOutput;
  bytes32 public committeePublicKey;

  uint256 public nextE3Id;

  mapping(uint256 => E3) public e3s;

  function request(address program) external {
    e3s[nextE3Id] = E3({
      seed: 0,
      committeeSize: IInterfold.CommitteeSize.Minimum,
      requestBlock: 0,
      inputWindow: [uint256(0), uint256(0)],
      encryptionSchemeId: bytes32(0),
      e3Program: IE3Program(address(0)),
      paramSet: 0, // Insecure512
      customParams: abi.encode(address(0), nextE3Id, 2, 0, 0),
      decryptionVerifier: IDecryptionVerifier(address(0)),
      pkVerifier: IPkVerifier(address(0)),
      committeePublicKey: committeePublicKey,
      ciphertextOutput: bytes32(0),
      plaintextOutput: plaintextOutput,
      requester: address(0),
      proofAggregationEnabled: false
    });

    IE3Program(program).validate(nextE3Id, 0, bytes(""), bytes(""), abi.encode(address(0), nextE3Id, 2, 0, 0));

    nextE3Id++;
  }

  function setPlaintextOutput(bytes memory plaintext) external {
    plaintextOutput = plaintext;
  }

  function setCommitteePublicKey(bytes32 publicKeyHash) external {
    committeePublicKey = publicKeyHash;
  }

  function getE3Stage(uint256) external view returns (IInterfold.E3Stage) {
    return IInterfold.E3Stage.KeyPublished;
  }

  function getE3(uint256) external view returns (E3 memory) {
    return
      E3({
        seed: 0,
        committeeSize: IInterfold.CommitteeSize.Minimum,
        requestBlock: 0,
        inputWindow: [uint256(0), block.timestamp + 100],
        encryptionSchemeId: bytes32(0),
        e3Program: IE3Program(address(0)),
        paramSet: 0, // Insecure512
        customParams: abi.encode(address(0), 0, 2, 0, 0),
        decryptionVerifier: IDecryptionVerifier(address(0)),
        pkVerifier: IPkVerifier(address(0)),
        committeePublicKey: committeePublicKey,
        ciphertextOutput: bytes32(0),
        plaintextOutput: plaintextOutput,
        requester: address(0),
        proofAggregationEnabled: false
      });
  }
}
