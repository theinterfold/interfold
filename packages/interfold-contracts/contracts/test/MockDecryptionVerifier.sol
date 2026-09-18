// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";

contract MockDecryptionVerifier is IDecryptionVerifier {
    error UnexpectedContext();

    uint256 public constant override threshold = 1;

    /// @dev Test-only: proofs whose first 4 bytes are `0xdeadbeef` revert with
    ///      `InvalidProof` so tests can exercise the wrapper failure path
    ///      (production wrapper now reverts instead of returning false).
    bytes4 private constant _FAIL_MAGIC = 0xdeadbeef;
    bytes4 private constant _RETURN_FALSE_MAGIC = 0xfafafafa;
    bool private checkContext;
    uint256 private expectedE3Id;
    bytes32 private expectedDecryptionDomain;
    bytes32 private expectedPlaintextOutputHash;
    bytes32 private expectedCommitteeHash;
    bytes32 private expectedCiphertextCommitment;
    bytes32 private expectedProofHash;

    function setExpectedContext(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external {
        expectedE3Id = e3Id;
        expectedDecryptionDomain = decryptionDomain;
        expectedPlaintextOutputHash = plaintextOutputHash;
        expectedCommitteeHash = committeeHash;
        expectedCiphertextCommitment = ciphertextCommitment;
        expectedProofHash = keccak256(proof);
        checkContext = true;
    }

    function verify(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view returns (bool success) {
        if (
            checkContext &&
            (e3Id != expectedE3Id ||
                decryptionDomain != expectedDecryptionDomain ||
                plaintextOutputHash != expectedPlaintextOutputHash ||
                committeeHash != expectedCommitteeHash ||
                ciphertextCommitment != expectedCiphertextCommitment ||
                keccak256(proof) != expectedProofHash)
        ) revert UnexpectedContext();
        if (proof.length >= 4 && bytes4(proof[0:4]) == _FAIL_MAGIC) {
            revert InvalidProof();
        }
        if (proof.length >= 4 && bytes4(proof[0:4]) == _RETURN_FALSE_MAGIC)
            return false;
        if (proof.length == 0) revert InvalidProof();
        success = true;
    }
}
