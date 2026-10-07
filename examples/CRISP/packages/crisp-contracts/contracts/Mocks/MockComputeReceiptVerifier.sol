// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity ^0.8.27;

import { IOpenVmReceiptVerifier } from "@interfold/contracts/contracts/interfaces/IOpenVmReceiptVerifier.sol";

contract MockComputeReceiptVerifier is IOpenVmReceiptVerifier {
  bytes32 public expectedJournalDigest;

  error UnexpectedJournalDigest(bytes32 actual, bytes32 expected);

  function setExpectedJournalDigest(bytes32 journalDigest) external {
    expectedJournalDigest = journalDigest;
  }

  function verify(bytes calldata, bytes32, bytes32 journalDigest) public view override {
    if (expectedJournalDigest != bytes32(0) && journalDigest != expectedJournalDigest) {
      revert UnexpectedJournalDigest(journalDigest, expectedJournalDigest);
    }
  }
}
