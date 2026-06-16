// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title DkgFoldAttestationLib
 * @notice Canonical EIP-712 digests for per-node DKG fold attestations.
 * @dev Must stay aligned with `DkgFoldAttestationPayload` in
 *      `crates/events/src/interfold_event/dkg_fold_attestation.rs`.
 *
 *      Domain binds `chainId` and `verifyingContract` (the
 *      `DkgFoldAttestationVerifier` address); the struct binds `e3Id`,
 *      `partyId`, and the two NodeFold commitments. Signatures cannot be
 *      replayed across chains, verifier deployments, or E3s.
 */
library DkgFoldAttestationLib {
    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    /// @dev `keccak256("InterfoldDkgFoldAttestation")`
    bytes32 public constant DOMAIN_NAME_HASH =
        keccak256(bytes("InterfoldDkgFoldAttestation"));

    /// @dev `keccak256("1")`
    bytes32 public constant DOMAIN_VERSION_HASH = keccak256(bytes("1"));

    /// @dev `keccak256("DkgFoldAttestation(uint256 e3Id,uint256 partyId,
    /// bytes32 skAggCommit,bytes32 esmAggCommit)")`
    bytes32 public constant TYPEHASH =
        keccak256(
            "DkgFoldAttestation(uint256 e3Id,uint256 partyId,bytes32 skAggCommit,bytes32 esmAggCommit)"
        );

    /// @notice One node's signed fold output.
    struct Attestation {
        uint256 partyId;
        bytes32 skAggCommit;
        bytes32 esmAggCommit;
        bytes signature;
    }

    /// @notice Maps sortition `partyId` to the operator that produced the fold.
    struct PartySlotBinding {
        uint256 partyId;
        address node;
    }

    /// @notice EIP-712 domain separator bound to `chainId` and `verifyingContract`.
    function domainSeparator(
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    EIP712_DOMAIN_TYPEHASH,
                    DOMAIN_NAME_HASH,
                    DOMAIN_VERSION_HASH,
                    chainId,
                    verifyingContract
                )
            );
    }

    /// @notice `hashStruct(DkgFoldAttestation)` per EIP-712.
    function structHash(
        uint256 e3Id,
        uint256 partyId,
        bytes32 skAggCommit,
        bytes32 esmAggCommit
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(TYPEHASH, e3Id, partyId, skAggCommit, esmAggCommit)
            );
    }

    /// @notice EIP-712 typed-data hash: `keccak256("\x19\x01" || domainSeparator || structHash)`.
    function typedDataHash(
        uint256 chainId,
        address verifyingContract,
        uint256 e3Id,
        uint256 partyId,
        bytes32 skAggCommit,
        bytes32 esmAggCommit
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    domainSeparator(chainId, verifyingContract),
                    structHash(e3Id, partyId, skAggCommit, esmAggCommit)
                )
            );
    }

    /// @notice Recover the EIP-712 signer for a fold attestation.
    function recoverSigner(
        uint256 chainId,
        address verifyingContract,
        uint256 e3Id,
        Attestation memory attestation
    ) internal pure returns (address) {
        bytes32 digest = typedDataHash(
            chainId,
            verifyingContract,
            e3Id,
            attestation.partyId,
            attestation.skAggCommit,
            attestation.esmAggCommit
        );
        return ECDSA.recover(digest, attestation.signature);
    }
}
