// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";

/// @notice Unit tests only: serves `getE3` and `getE3Stage` to `NegotiationProgram`. A test sets the
/// window, the requester, the committee key, the published plaintext and the stage of each E3, and
/// calls `request` to run `validate` as Interfold does.
contract MockInterfold {
  mapping(uint256 => E3) private _e3s;
  mapping(uint256 => IInterfold.E3Stage) private _stages;

  function setE3(uint256 e3Id, uint256 inputDeadline, bytes32 committeePublicKey, address requester) external {
    E3 storage e3 = _e3s[e3Id];
    e3.inputWindow = [uint256(0), inputDeadline];
    e3.committeePublicKey = committeePublicKey;
    e3.requester = requester;
  }

  function setInputDeadline(uint256 e3Id, uint256 inputDeadline) external {
    _e3s[e3Id].inputWindow = [uint256(0), inputDeadline];
  }

  function setPlaintext(uint256 e3Id, bytes calldata plaintext) external {
    _e3s[e3Id].plaintextOutput = plaintext;
    _stages[e3Id] = IInterfold.E3Stage.Complete;
  }

  function setStage(uint256 e3Id, IInterfold.E3Stage stage) external {
    _stages[e3Id] = stage;
  }

  /// @dev Runs `validate` with this contract as the caller, as `Interfold.request` does.
  function request(uint256 e3Id, IE3Program program, bytes calldata customParams) external returns (bytes32) {
    return program.validate(e3Id, 0, "", "", customParams);
  }

  function getE3(uint256 e3Id) external view returns (E3 memory) {
    return _e3s[e3Id];
  }

  function getE3Stage(uint256 e3Id) external view returns (IInterfold.E3Stage) {
    return _stages[e3Id];
  }
}
