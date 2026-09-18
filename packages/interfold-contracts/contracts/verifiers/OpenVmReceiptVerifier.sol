// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    IOpenVmReceiptVerifier
} from "../interfaces/IOpenVmReceiptVerifier.sol";

interface IOpenVmHalo2Verifier {
    function verify(
        bytes calldata publicValues,
        bytes calldata proofData,
        bytes32 appExeCommit,
        bytes32 appVmCommit
    ) external view;
}

/// @notice Verifies the Halo2 proof and binds it to one OpenVM executable and VM.
contract OpenVmReceiptVerifier is IOpenVmReceiptVerifier {
    uint256 private constant SCALAR_MODULUS =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 private constant PROOF_DATA_LENGTH = (12 + 43) * 32;
    bytes32 public constant IMAGE_DOMAIN =
        keccak256("INTERFOLD_OPENVM_RECEIPT_V1");

    IOpenVmHalo2Verifier public immutable verifier;
    bytes32 public immutable appExeCommit;
    bytes32 public immutable appVmCommit;
    bytes32 public immutable imageId;

    error InvalidVerifier();
    error InvalidAppCommitment();
    error WrongImageId();
    error InvalidSealVersion();
    error InvalidSealEncoding();
    error InvalidProofDataLength();
    error JournalDigestMismatch();

    constructor(
        IOpenVmHalo2Verifier verifier_,
        bytes32 appExeCommit_,
        bytes32 appVmCommit_
    ) {
        if (address(verifier_).code.length == 0) revert InvalidVerifier();
        if (
            appExeCommit_ == bytes32(0) ||
            appVmCommit_ == bytes32(0) ||
            uint256(appExeCommit_) >= SCALAR_MODULUS ||
            uint256(appVmCommit_) >= SCALAR_MODULUS
        ) revert InvalidAppCommitment();
        verifier = verifier_;
        appExeCommit = appExeCommit_;
        appVmCommit = appVmCommit_;
        imageId = keccak256(
            abi.encode(
                IMAGE_DOMAIN,
                address(verifier_),
                appExeCommit_,
                appVmCommit_
            )
        );
    }

    /// @notice Check the caller's journal digest and verify the corresponding OpenVM public values.
    /// @dev The seal contains a version, Halo2 proof data, and all nine journal words.
    function verify(
        bytes calldata seal,
        bytes32 expectedImageId,
        bytes32 expectedJournalDigest
    ) external view {
        if (expectedImageId != imageId) revert WrongImageId();
        (uint8 version, bytes memory proofData, bytes32[9] memory words) = abi
            .decode(seal, (uint8, bytes, bytes32[9]));
        if (version != 1) revert InvalidSealVersion();
        if (keccak256(seal) != keccak256(abi.encode(version, proofData, words)))
            revert InvalidSealEncoding();
        if (proofData.length != PROOF_DATA_LENGTH)
            revert InvalidProofDataLength();

        bytes memory callerJournal = abi.encode(words);
        if (sha256(callerJournal) != expectedJournalDigest)
            revert JournalDigestMismatch();

        verifier.verify(
            abi.encodePacked(expectedJournalDigest),
            proofData,
            appExeCommit,
            appVmCommit
        );
    }
}
