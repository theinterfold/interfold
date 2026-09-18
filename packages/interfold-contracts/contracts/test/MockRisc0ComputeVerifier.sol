// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

contract MockRisc0ComputeVerifier {
    error UnexpectedSealHash(bytes32 actual, bytes32 expected);
    error UnexpectedImageId(bytes32 actual, bytes32 expected);
    error UnexpectedJournalDigest(bytes32 actual, bytes32 expected);

    bytes32 public expectedSealHash;
    bytes32 public expectedImageId;
    bytes32 public expectedJournalDigest;

    function setExpectedCall(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external {
        expectedSealHash = keccak256(seal);
        expectedImageId = imageId;
        expectedJournalDigest = journalDigest;
    }

    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view {
        bytes32 sealHash = keccak256(seal);
        if (sealHash != expectedSealHash)
            revert UnexpectedSealHash(sealHash, expectedSealHash);
        if (imageId != expectedImageId)
            revert UnexpectedImageId(imageId, expectedImageId);
        if (journalDigest != expectedJournalDigest)
            revert UnexpectedJournalDigest(
                journalDigest,
                expectedJournalDigest
            );
    }
}
