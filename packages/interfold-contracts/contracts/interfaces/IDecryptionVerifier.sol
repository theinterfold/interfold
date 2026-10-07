// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/**
 * @title IDecryptionVerifier
 * @notice Interface for the DecryptionAggregator (EVM) proof verifier.
 * @dev The DecryptionAggregator circuit internally verifies the C6-fold and C7
 *      (decrypted_shares_aggregation) sub-proofs; this on-chain wrapper verifies
 *      the final EVM proof and enforces:
 *        - the immutable recursive sub-circuit VK hashes
 *        - the plaintext slot matches the caller-supplied hash
 *        - a domain-binding slot supplied by Interfold and derived from
 *          (chainId, Interfold address, e3Id, committeeHash,
 *           ciphertextOutputHash, committeePublicKey)
 *        - the final proof's SAFE ciphertext commitment matches the commitment stored for the E3
 *      and reverts on any mismatch.
 */
interface IDecryptionVerifier {
    /// @notice Reconstruction threshold compiled into the verifier.
    function threshold() external view returns (uint256);

    /// @notice Proof was structurally well-formed but the underlying honk
    ///         verifier rejected it. Used in place of a `bool false` return.
    error InvalidProof();
    /// @notice `publicInputs` is shorter than the layout the wrapper expects
    ///         (must hold the two VK-hash slots, domain and ciphertext-binding
    ///         slots, and the 50 message-coefficient slots).
    error InvalidPublicInputsLength();
    /// @notice One of the recursive-aggregation sub-circuit VK hashes embedded
    ///         in the proof does not match the immutable value committed at
    ///         construction time.
    error VkHashMismatch();
    /// @notice The 50 plaintext-coefficient slots do not hash to
    ///         `plaintextOutputHash`.
    error PlaintextHashMismatch();
    /// @notice The domain-binding public-input slot does not equal the value
    ///         recomputed on-chain from the call context.
    error DomainBindingMismatch();
    /// @notice The proof's SAFE ciphertext commitment does not match the E3 commitment.
    error CiphertextCommitmentMismatch();
    /// @notice A `party_id` returned by the proof is not present in the
    ///         registry's stored DKG anchors for this E3.
    error DkgAnchorNotFound();
    /// @notice The proof's `expected_sk`/`expected_esm` commitment for a
    ///         party does not match the registry's stored DKG anchor.
    error DkgAnchorMismatch();

    /// @notice Verify a DecryptionAggregator EVM proof and bind it to the E3
    ///         domain recomputed by Interfold and the DKG anchors stored for it.
    /// @param e3Id Identifier used to resolve the stored DKG anchors. It is
    ///        passed separately because it cannot be recovered from the domain hash.
    /// @param decryptionDomain `keccak256(abi.encode(chainId, interfold, e3Id,
    ///        committeeHash, ciphertextOutputHash, committeePublicKey))`.
    /// @param plaintextOutputHash `keccak256(plaintextOutput)` expected by the Interfold.
    /// @param committeeHash `keccak256(abi.encodePacked(topNodes))` for the on-chain committee.
    /// @param ciphertextCommitment Circuit-compatible SAFE commitment to the decoded BFV ciphertext.
    /// @param proof ABI-encoded `(bytes rawProof, bytes32[] publicInputs)`.
    /// @return success Always `true` on success; the wrapper reverts on any failure.
    function verify(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view returns (bool success);
}
