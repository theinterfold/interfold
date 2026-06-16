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
 *        - a domain-binding slot binding the proof to
 *          (chainId, this, e3Id, committeeRoot, sortedNodes, ciphertextOutputHash,
 *           committeePublicKey, plaintextOutputHash)
 *      and reverts on any mismatch.
 */
interface IDecryptionVerifier {
    /// @notice Proof was structurally well-formed but the underlying honk
    ///         verifier rejected it. Used in place of a `bool false` return.
    error InvalidProof();
    /// @notice `publicInputs` is shorter than the layout the wrapper expects
    ///         (must hold the two VK-hash slots, the domain-binding slot and the
    ///         100 message-coefficient slots).
    error InvalidPublicInputsLength();
    /// @notice One of the recursive-aggregation sub-circuit VK hashes embedded
    ///         in the proof does not match the immutable value committed at
    ///         construction time.
    error VkHashMismatch();
    /// @notice The 100 plaintext-coefficient slots do not hash to
    ///         `plaintextOutputHash`.
    error PlaintextHashMismatch();
    /// @notice The domain-binding public-input slot does not equal the value
    ///         recomputed on-chain from the call context.
    error DomainBindingMismatch();

    /// @notice Verify a DecryptionAggregator EVM proof and bind it to the full
    ///         on-chain call context.
    /// @param e3Id Identifier of the E3 the plaintext was decrypted for.
    /// @param committeeRoot Ciphernode IMT root snapshotted at committee request time
    ///        (`CiphernodeRegistry.rootAt(e3Id)`).
    /// @param sortedNodes The on-chain-selected committee (`c.topNodes`), bound into
    ///        the domain-binding hash.
    /// @param ciphertextOutputHash The previously-published ciphertext hash
    ///        (`e3.ciphertextOutput`).
    /// @param committeePublicKey The committee's aggregated PK commitment
    ///        (`e3.committeePublicKey`).
    /// @param plaintextOutputHash `keccak256(plaintextOutput)` expected by the Interfold.
    /// @param committeeHash `keccak256(abi.encodePacked(topNodes))` for the on-chain committee.
    /// @param proof ABI-encoded `(bytes rawProof, bytes32[] publicInputs)`.
    /// @return success Always `true` on success; the wrapper reverts on any failure.
    function verify(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 ciphertextOutputHash,
        bytes32 committeePublicKey,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes calldata proof
    ) external view returns (bool success);
}
