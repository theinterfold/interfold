// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";

/// @notice The fields of an E3 that the program reads.
struct E3Info {
  address requester;
  uint256 windowStart;
  uint256 windowEnd;
  uint8 committeeSize;
  bytes32 key;
  bytes32 encryptionSchemeId;
  bytes plaintext;
}

/// @title Reader of the E3 record of Interfold.
/// @notice The decoder of the whole `E3` struct is large. It lives in this external library, so that
/// `TokenLaunchProgram` stays below the contract size limit.
library E3Reader {
  function read(address interfold, uint256 e3Id) public view returns (E3Info memory info) {
    E3 memory e3 = IInterfold(interfold).getE3(e3Id);
    info = E3Info(
      e3.requester,
      e3.inputWindow[0],
      e3.inputWindow[1],
      uint8(e3.committeeSize),
      e3.committeePublicKey,
      e3.encryptionSchemeId,
      e3.plaintextOutput
    );
  }
}
