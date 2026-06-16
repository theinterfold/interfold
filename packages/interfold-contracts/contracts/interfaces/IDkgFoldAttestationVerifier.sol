// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

/**
 * @title IDkgFoldAttestationVerifier
 * @notice Verifies per-node DKG fold ECDSA attestations against a DkgAggregator proof.
 * @dev Invoked via external call from the registry so verification does not share its stack frame.
 */
interface IDkgFoldAttestationVerifier {
    /// @notice Verify attestations and return anchor arrays indexed by proof party-id slot.
    /// @param registry Ciphernode registry (`isCommitteeMemberActive` callback).
    /// @param chainId EIP-712 chain id used in attestation digests.
    /// @param e3Id E3 identifier.
    /// @param proof ABI-encoded `(bytes rawProof, bytes32[] publicInputs)` from the aggregator.
    /// @param dkgAttestationBundle ABI-encoded
    ///        `(Attestation[] attestations, PartySlotBinding[] bindings)`; bindings sorted by ascending `partyId`.
    /// @return partyIds Honest party ids (proof slot order)
    /// @return skAggCommits Per-party sk aggregate commitments
    /// @return esmAggCommits Per-party esm aggregate commitments
    function verify(
        address registry,
        uint256 chainId,
        uint256 e3Id,
        bytes calldata proof,
        bytes calldata dkgAttestationBundle
    )
        external
        view
        returns (
            uint256[] memory partyIds,
            bytes32[] memory skAggCommits,
            bytes32[] memory esmAggCommits
        );
}
