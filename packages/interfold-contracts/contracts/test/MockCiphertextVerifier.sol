// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ICiphertextVerifier } from "../interfaces/ICiphertextVerifier.sol";

contract MockCiphertextVerifier is ICiphertextVerifier {
    error UnexpectedContext();

    bool public result = true;
    bool private checkContext;
    uint256 private expectedE3Id;
    bytes32 private expectedEncryptionSchemeId;
    bytes32 private expectedParamsHash;
    bytes32 private expectedCommitteePublicKey;
    bytes32 private expectedCiphertextOutputHash;
    bytes32 private expectedCiphertextCommitment;
    bytes32 private expectedProofHash;

    function setResult(bool value) external {
        result = value;
    }

    function setExpectedContext(
        uint256 e3Id,
        bytes32 encryptionSchemeId,
        bytes32 paramsHash,
        bytes32 committeePublicKey,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external {
        expectedE3Id = e3Id;
        expectedEncryptionSchemeId = encryptionSchemeId;
        expectedParamsHash = paramsHash;
        expectedCommitteePublicKey = committeePublicKey;
        expectedCiphertextOutputHash = ciphertextOutputHash;
        expectedCiphertextCommitment = ciphertextCommitment;
        expectedProofHash = keccak256(proof);
        checkContext = true;
    }

    function verify(
        uint256 e3Id,
        bytes32 encryptionSchemeId,
        bytes32 paramsHash,
        bytes32 committeePublicKey,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view returns (bool) {
        if (
            checkContext &&
            (e3Id != expectedE3Id ||
                encryptionSchemeId != expectedEncryptionSchemeId ||
                paramsHash != expectedParamsHash ||
                committeePublicKey != expectedCommitteePublicKey ||
                ciphertextOutputHash != expectedCiphertextOutputHash ||
                ciphertextCommitment != expectedCiphertextCommitment ||
                keccak256(proof) != expectedProofHash)
        ) revert UnexpectedContext();
        return result;
    }
}
