// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import {
    ISynchronizedDkgPublication,
    ISynchronizedDkgPublicationVerifier,
    ISynchronizedDkgRequestContext
} from "../interfaces/ISynchronizedDkgPublication.sol";
import {
    SynchronizedDkgAttestationLib
} from "./SynchronizedDkgAttestationLib.sol";
import { BfvProtocol } from "./BfvProtocol.sol";
import { CommitteeHashLib } from "./CommitteeHashLib.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { E3 } from "../interfaces/IE3.sol";
import { IPkVerifier } from "../interfaces/IPkVerifier.sol";
import {
    IDkgFoldAttestationVerifier
} from "../interfaces/IDkgFoldAttestationVerifier.sol";

/// @notice Called by the registry with request-frozen facts, never caller-selected authority.
library DkgPublicationLib {
    /// @dev The controller has already stored the request's verifier and crypto identity.
    function establishRequestContext(
        IInterfold controller,
        uint256 e3Id
    ) external returns (bool) {
        bytes32 identity = ISynchronizedDkgRequestContext(address(controller))
            .e3CryptoConfigIds(e3Id);
        if (!BfvProtocol.isSynchronizedMinimum(identity)) return false;
        E3 memory e3 = controller.getE3(e3Id);
        _synchronizedVerifier(
            address(controller),
            address(e3.pkVerifier),
            identity
        );
        emit ISynchronizedDkgPublication.SynchronizedDkgContextEstablished(
            e3Id,
            address(this),
            address(e3.pkVerifier),
            identity
        );
        return true;
    }

    struct SecretSharedContext {
        uint256 e3Id;
        IInterfold controller;
        IDkgFoldAttestationVerifier attestationVerifier;
        uint256 committeeRoot;
        bytes32 pkCommitment;
    }

    /// @dev Legacy SS publication, extracted without changing verification order or ESM meaning.
    function publishSecretShared(
        ICiphernodeRegistry.Committee storage committee,
        mapping(uint256 => bytes32) storage publicKeyHashes,
        mapping(uint256 => uint256[]) storage partyIds,
        mapping(uint256 => bytes32[]) storage skCommits,
        mapping(uint256 => bytes32[]) storage esmCommits,
        SecretSharedContext memory context,
        bytes calldata proof,
        bytes calldata attestationBundle
    ) external {
        require(
            committee.stage == ICiphernodeRegistry.CommitteeStage.Finalized,
            ICiphernodeRegistry.CommitteeNotFinalized()
        );
        require(
            committee.activeCount >= committee.threshold[0],
            ICiphernodeRegistry.ThresholdNotMet()
        );
        require(
            committee.publicKey == bytes32(0),
            ICiphernodeRegistry.CommitteeAlreadyPublished()
        );
        require(
            context.pkCommitment != bytes32(0),
            ICiphernodeRegistry.PkCommitmentRequired()
        );
        committee.committeeHash = CommitteeHashLib.hash(committee.topNodes);
        committee.publicKey = context.pkCommitment;
        publicKeyHashes[context.e3Id] = context.pkCommitment;
        (
            uint256[] memory ids,
            bytes32[] memory sk,
            bytes32[] memory esm
        ) = _verifySecretShared(committee, context, proof, attestationBundle);
        partyIds[context.e3Id] = ids;
        skCommits[context.e3Id] = sk;
        esmCommits[context.e3Id] = esm;
        context.controller.onCommitteePublished(
            context.e3Id,
            context.pkCommitment
        );
        emit ICiphernodeRegistry.CommitteeProofPublished(
            context.e3Id,
            committee.topNodes,
            context.pkCommitment,
            proof
        );
    }

    function _verifySecretShared(
        ICiphernodeRegistry.Committee storage committee,
        SecretSharedContext memory context,
        bytes calldata proof,
        bytes calldata attestationBundle
    )
        private
        view
        returns (uint256[] memory, bytes32[] memory, bytes32[] memory)
    {
        E3 memory e3 = context.controller.getE3(context.e3Id);
        require(
            !BfvProtocol.isSynchronizedMinimum(
                ISynchronizedDkgRequestContext(address(context.controller))
                    .e3CryptoConfigIds(context.e3Id)
            ),
            ISynchronizedDkgPublication.SynchronizedDkgPublicationRequired()
        );
        require(proof.length > 0, ICiphernodeRegistry.DkgProofRequired());
        // Bind to the on-chain committee, never caller-supplied nodes (C-08).
        if (
            !e3.pkVerifier.verify(
                context.e3Id,
                context.committeeRoot,
                committee.topNodes,
                context.pkCommitment,
                committee.committeeHash,
                proof
            )
        ) revert IPkVerifier.InvalidProof();
        require(
            attestationBundle.length > 0,
            ICiphernodeRegistry.FoldAttestationsRequired()
        );
        require(
            address(context.attestationVerifier) != address(0),
            ICiphernodeRegistry.FoldAttestationVerifierNotSet()
        );
        return
            context.attestationVerifier.verify(
                address(this),
                block.chainid,
                context.e3Id,
                proof,
                attestationBundle
            );
    }

    function publishSynchronized(
        mapping(uint256 => ISynchronizedDkgPublication.Authority)
            storage authorities,
        mapping(uint256 => bytes32) storage publicKeyHashes,
        ICiphernodeRegistry.Committee storage committee,
        IInterfold controller,
        uint256 e3Id,
        ISynchronizedDkgPublication.Publication calldata publication
    ) external {
        require(
            committee.stage == ICiphernodeRegistry.CommitteeStage.Finalized,
            ICiphernodeRegistry.CommitteeNotFinalized()
        );
        require(
            committee.activeCount >= committee.threshold[0],
            ICiphernodeRegistry.ThresholdNotMet()
        );
        require(
            committee.publicKey == bytes32(0),
            ICiphernodeRegistry.CommitteeAlreadyPublished()
        );
        require(
            publication.pkCommitment != bytes32(0),
            ICiphernodeRegistry.PkCommitmentRequired()
        );
        require(
            publication.proof.length > 0,
            ICiphernodeRegistry.DkgProofRequired()
        );
        E3 memory e3 = controller.getE3(e3Id);
        ISynchronizedDkgPublication.Authority memory authority = verify(
            address(controller),
            e3Id,
            address(e3.pkVerifier),
            ISynchronizedDkgRequestContext(address(controller))
                .e3CryptoConfigIds(e3Id),
            committee.topNodes,
            publication
        );
        // The canonical lifecycle callback enforces the DKG/input deadlines and atomically
        // reverts these writes on failure. No registry/global verifier is selected at publication.
        authorities[e3Id] = authority;
        committee.committeeHash = CommitteeHashLib.hash(committee.topNodes);
        committee.publicKey = publication.pkCommitment;
        publicKeyHashes[e3Id] = publication.pkCommitment;
        controller.onCommitteePublished(e3Id, publication.pkCommitment);
        emit ISynchronizedDkgPublication.SynchronizedDkgAuthorityPublished(
            e3Id,
            authority
        );
        emit ICiphernodeRegistry.CommitteeProofPublished(
            e3Id,
            committee.topNodes,
            publication.pkCommitment,
            publication.proof
        );
    }

    function getSynchronized(
        mapping(uint256 => ISynchronizedDkgPublication.Authority)
            storage authorities,
        uint256 e3Id
    ) external view returns (ISynchronizedDkgPublication.Authority memory) {
        return authorities[e3Id];
    }

    function verify(
        address interfold,
        uint256 e3Id,
        address verifierAddress,
        bytes32 cryptoConfigId,
        address[] memory committee,
        ISynchronizedDkgPublication.Publication calldata publication
    )
        private
        view
        returns (ISynchronizedDkgPublication.Authority memory authority)
    {
        ISynchronizedDkgPublicationVerifier verifier = _synchronizedVerifier(
            interfold,
            verifierAddress,
            cryptoConfigId
        );
        if (
            committee.length != BfvProtocol.MINIMUM_N ||
            publication.partyIds.length != BfvProtocol.MINIMUM_H ||
            publication.signatures.length != publication.partyIds.length
        )
            revert ISynchronizedDkgPublication
                .InvalidSynchronizedDkgPublication();

        authority.version = 1;
        authority.verifier = verifierAddress;
        authority.cryptoConfigId = cryptoConfigId;
        authority.setupBinding = verifier.setupBinding(e3Id, committee);
        authority.dealerBatch = publication.dealerBatch;
        authority.pkCommitment = publication.pkCommitment;
        authority.partyIds = publication.partyIds;
        (
            authority.skAggCommits,
            authority.keyBundleCommits,
            authority.thresholdPkCommits
        ) = verifier.verify(
            e3Id,
            committee,
            publication.partyIds,
            publication.pkCommitment,
            publication.dealerBatch,
            publication.proof
        );
        _verifyConsent(e3Id, committee, publication.signatures, authority);
    }

    function _synchronizedVerifier(
        address interfold,
        address verifierAddress,
        bytes32 cryptoConfigId
    ) private view returns (ISynchronizedDkgPublicationVerifier verifier) {
        verifier = ISynchronizedDkgPublicationVerifier(verifierAddress);
        if (
            !BfvProtocol.isSynchronizedMinimum(cryptoConfigId) ||
            verifier.INTERFOLD() != interfold ||
            verifier.CRYPTO_CONFIG_ID() != cryptoConfigId ||
            verifier.N() != BfvProtocol.MINIMUM_N ||
            verifier.H() != BfvProtocol.MINIMUM_H
        )
            revert ISynchronizedDkgPublication
                .InvalidSynchronizedDkgPublication();
    }

    function _verifyConsent(
        uint256 e3Id,
        address[] memory committee,
        bytes[] calldata signatures,
        ISynchronizedDkgPublication.Authority memory authority
    ) private view {
        uint256 h = authority.partyIds.length;
        if (
            h == 0 ||
            authority.skAggCommits.length != h ||
            authority.keyBundleCommits.length != h ||
            authority.thresholdPkCommits.length != h
        )
            revert ISynchronizedDkgPublication
                .InvalidSynchronizedDkgPublication();
        SynchronizedDkgAttestationLib.Context
            memory context = SynchronizedDkgAttestationLib.Context({
                registry: address(this),
                e3Id: e3Id,
                cryptoConfigId: authority.cryptoConfigId,
                setupBinding: authority.setupBinding,
                rosterHash: keccak256(abi.encode(authority.partyIds)),
                dealerBatch: authority.dealerBatch,
                pkCommitment: authority.pkCommitment
            });
        for (uint256 i; i < h; ++i) {
            uint256 partyId = authority.partyIds[i];
            if (
                partyId >= committee.length ||
                (i > 0 && authority.partyIds[i - 1] >= partyId)
            )
                revert ISynchronizedDkgPublication
                    .InvalidSynchronizedDkgPublication();
            address node = committee[partyId];
            if (
                !ICiphernodeRegistry(address(this)).isCommitteeMemberActive(
                    e3Id,
                    node
                ) ||
                SynchronizedDkgAttestationLib.recover(
                    authority.verifier,
                    context,
                    partyId,
                    authority.skAggCommits[i],
                    authority.keyBundleCommits[i],
                    signatures[i]
                ) !=
                node
            )
                revert ISynchronizedDkgPublication
                    .InvalidSynchronizedDkgPublication();
        }
    }
}
