// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";

/// @notice Verifies signed committee accusations outside the size-constrained manager.
library SlashingEvidenceLib {
    bytes32 internal constant VOTE_TYPEHASH =
        keccak256(
            "AccusationVote(uint256 e3Id,bytes32 accusationId,"
            "address voter,bytes32 dataHash,uint256 issuedAt,uint256 deadline)"
        );
    uint256 internal constant CLOCK_SKEW = 30 seconds;
    uint256 internal constant FIRST_MULTIROW_PROOF_TYPE = 11;
    uint256 internal constant LAST_MULTIROW_PROOF_TYPE = 14;
    uint256 internal constant LBFV_ROW_INSTANCES = 5;

    struct AttestationEvidence {
        uint256 proofType;
        uint256 proofInstance;
        address[] voters;
        bytes32[] dataHashes;
        bytes evidence;
        uint256 issuedAt;
        uint256 deadline;
        bytes[] signatures;
    }

    struct AttestationContext {
        uint256 e3Id;
        address operator;
        bytes32 accusationId;
        bytes32 sharedDataHash;
        uint256 issuedAt;
        uint256 deadline;
        bytes32 domainSeparator;
        ICiphernodeRegistry registry;
    }

    function verifyAttestationEvidence(
        bytes calldata proof,
        uint256 e3Id,
        address operator,
        address registryAddress,
        uint64 voteValidity,
        uint64 slashSubmissionDeadline,
        bytes32 domainSeparator
    ) external view {
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        AttestationEvidence memory attestation = _decodeEvidence(proof);
        bool isMultirow = attestation.proofType >= FIRST_MULTIROW_PROOF_TYPE &&
            attestation.proofType <= LAST_MULTIROW_PROOF_TYPE;
        if (
            (isMultirow &&
                attestation.proofInstance >= LBFV_ROW_INSTANCES) ||
            (!isMultirow && attestation.proofInstance != 0)
        ) revert ISlashingManager.InvalidProof();
        uint256 numVotes = attestation.voters.length;
        if (
            numVotes != attestation.dataHashes.length ||
            numVotes != attestation.signatures.length
        ) revert ISlashingManager.InvalidProof();

        _validateWindow(
            registry,
            voteValidity,
            slashSubmissionDeadline,
            attestation.issuedAt,
            attestation.deadline
        );

        (, uint32 thresholdM, , ) = registry.getCommitteeViability(e3Id);
        if (thresholdM == 0) revert ISlashingManager.InvalidProposal();
        if (numVotes < thresholdM) {
            revert ISlashingManager.InsufficientAttestations();
        }

        bytes32 sharedDataHash = attestation.dataHashes[0];
        if (keccak256(attestation.evidence) != sharedDataHash) {
            revert ISlashingManager.InvalidProof();
        }
        AttestationContext memory context = AttestationContext({
            e3Id: e3Id,
            operator: operator,
            accusationId: _accusationId(
                e3Id,
                operator,
                attestation.proofType,
                attestation.proofInstance
            ),
            sharedDataHash: sharedDataHash,
            issuedAt: attestation.issuedAt,
            deadline: attestation.deadline,
            domainSeparator: domainSeparator,
            registry: registry
        });
        _verifyVotes(attestation, context);
    }

    function _decodeEvidence(
        bytes calldata proof
    ) private pure returns (AttestationEvidence memory attestation) {
        (
            attestation.proofType,
            attestation.proofInstance,
            attestation.voters,
            attestation.dataHashes,
            attestation.evidence,
            attestation.issuedAt,
            attestation.deadline,
            attestation.signatures
        ) = abi.decode(
            proof,
            (uint256, uint256, address[], bytes32[], bytes, uint256, uint256, bytes[])
        );
    }

    function _accusationId(
        uint256 e3Id,
        address operator,
        uint256 proofType,
        uint256 proofInstance
    ) private view returns (bytes32) {
        if (proofInstance == 0) {
            return
                keccak256(
                    abi.encodePacked(
                        block.chainid,
                        e3Id,
                        operator,
                        proofType
                    )
                );
        }
        return
            keccak256(
                abi.encodePacked(
                    block.chainid,
                    e3Id,
                    operator,
                    proofType,
                    proofInstance
                )
            );
    }

    function _verifyVotes(
        AttestationEvidence memory attestation,
        AttestationContext memory context
    ) private view {
        address previousVoter;
        for (uint256 i; i < attestation.voters.length; i++) {
            address voter = attestation.voters[i];
            if (voter <= previousVoter) {
                revert ISlashingManager.DuplicateVoter();
            }
            previousVoter = voter;
            if (voter == context.operator) {
                revert ISlashingManager.VoterIsAccused();
            }
            if (attestation.dataHashes[i] != context.sharedDataHash) {
                revert ISlashingManager.EquivocationDetected();
            }
            if (
                !context.registry.isCommitteeMemberActive(context.e3Id, voter)
            ) {
                revert ISlashingManager.VoterNotInCommittee();
            }
            _verifyVote(context, voter, attestation.signatures[i]);
        }
    }

    function _validateWindow(
        ICiphernodeRegistry registry,
        uint64 voteValidity,
        uint64 slashSubmissionDeadline,
        uint256 issuedAt,
        uint256 deadline
    ) private view {
        if (voteValidity == 0 || registry.accusationVoteValidity() == 0) {
            revert ISlashingManager.AccusationSlashingDisabled();
        }
        if (block.timestamp > slashSubmissionDeadline) {
            revert ISlashingManager.SlashSubmissionDeadlinePassed();
        }
        if (issuedAt > block.timestamp + CLOCK_SKEW) {
            revert ISlashingManager.AccusationIssuedInFuture();
        }
        if (deadline < issuedAt || deadline - issuedAt > voteValidity) {
            revert ISlashingManager.InvalidAccusationWindow();
        }
        if (block.timestamp > deadline) {
            revert ISlashingManager.SignatureExpired();
        }
    }

    function _verifyVote(
        AttestationContext memory context,
        address voter,
        bytes memory signature
    ) private pure {
        bytes32 structHash = keccak256(
            abi.encode(
                VOTE_TYPEHASH,
                context.e3Id,
                context.accusationId,
                voter,
                context.sharedDataHash,
                context.issuedAt,
                context.deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", context.domainSeparator, structHash)
        );
        if (ECDSA.recover(digest, signature) != voter) {
            revert ISlashingManager.InvalidVoteSignature();
        }
    }
}
