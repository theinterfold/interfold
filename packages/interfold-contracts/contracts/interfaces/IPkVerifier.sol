// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/**
 * @title IPkVerifier
 * @notice Interface for the DkgAggregator (EVM) proof verifier.
 * @dev The DkgAggregator circuit internally verifies the node-fold and C5
 *      (pk_aggregation) sub-proofs; this on-chain wrapper verifies the final
 *      EVM proof and enforces:
 *        - the immutable recursive sub-circuit VK hashes
 *        - the aggregated public-key commitment slot
 *        - a domain-binding slot binding the proof to
 *          (chainId, this, e3Id, committeeRoot, sortedNodes, pkCommitment)
 *      and reverts on any mismatch.
 */
interface IPkVerifier {
    /// @notice Proof was structurally well-formed but the underlying honk
    ///         verifier rejected it. Used in place of a `bool false` return.
    error InvalidProof();
    /// @notice `publicInputs` is shorter than the layout the wrapper expects
    ///         (must hold at least the two VK-hash slots, the domain-binding slot
    ///         and the pk-commitment slot).
    error InvalidPublicInputsLength();
    /// @notice One of the recursive-aggregation sub-circuit VK hashes embedded
    ///         in the proof does not match the immutable value committed at
    ///         construction time.
    error VkHashMismatch();
    /// @notice The last public input does not equal the caller-supplied
    ///         `pkCommitment`.
    error PkCommitmentMismatch();
    /// @notice The domain-binding public-input slot does not equal the value
    ///         recomputed on-chain from the call context.
    error DomainBindingMismatch();

    /// @notice Verify a DkgAggregator EVM proof and bind it to the full
    ///         on-chain call context.
    /// @param e3Id Identifier of the E3 the committee was selected for.
    /// @param committeeRoot Ciphernode IMT root snapshotted at committee request time
    ///        (`CiphernodeRegistry.rootAt(e3Id)`).
    /// @param sortedNodes The on-chain-selected committee (`c.topNodes`), bound into
    ///        the domain-binding hash so a proof for one committee cannot be replayed
    ///        for another.
    /// @param pkCommitment Hash-based aggregated PK commitment the proof must attest to
    ///        (equals `publicInputs[publicInputs.length - 1]`).
    /// @param committeeHash `keccak256(abi.encodePacked(topNodes))` for the on-chain committee.
    /// @param proof ABI-encoded `(bytes rawProof, bytes32[] publicInputs)`.
    /// @return success Always `true` on success; the wrapper reverts on any failure.
    function verify(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 pkCommitment,
        bytes32 committeeHash,
        bytes calldata proof
    ) external view returns (bool success);
}
