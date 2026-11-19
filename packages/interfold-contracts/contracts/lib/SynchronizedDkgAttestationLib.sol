// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Exact synchronized publication consent; deliberately distinct from SS attestations.
library SynchronizedDkgAttestationLib {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 private constant NAME_HASH =
        keccak256("InterfoldSynchronizedDkgAttestation");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant TYPEHASH =
        keccak256(
            "SynchronizedDkgAttestation(address registry,uint256 e3Id,bytes32 cryptoConfigId,"
            "bytes32 setupBinding,bytes32 rosterHash,bytes32 dealerBatch,bytes32 pkCommitment,"
            "uint256 partyId,bytes32 skAggCommit,bytes32 keyBundleCommit)"
        );

    struct Context {
        address registry;
        uint256 e3Id;
        bytes32 cryptoConfigId;
        bytes32 setupBinding;
        /// keccak256(abi.encode(uint256[] canonicalSelectedPartyIds)).
        bytes32 rosterHash;
        bytes32 dealerBatch;
        bytes32 pkCommitment;
    }

    function digest(
        uint256 chainId,
        address verifier,
        Context memory context,
        uint256 partyId,
        bytes32 skAggCommit,
        bytes32 keyBundleCommit
    ) internal pure returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                chainId,
                verifier
            )
        );
        // Context is entirely static, so its ABI tuple is the exact flattened EIP-712 field order.
        bytes32 statement = keccak256(
            abi.encode(TYPEHASH, context, partyId, skAggCommit, keyBundleCommit)
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, statement));
    }

    function recover(
        address verifier,
        Context memory context,
        uint256 partyId,
        bytes32 skAggCommit,
        bytes32 keyBundleCommit,
        bytes memory signature
    ) internal view returns (address) {
        return
            ECDSA.recover(
                digest(
                    block.chainid,
                    verifier,
                    context,
                    partyId,
                    skAggCommit,
                    keyBundleCommit
                ),
                signature
            );
    }
}
