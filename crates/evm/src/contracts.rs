// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Minimal stable Solidity ABI definitions for on-chain contracts.
//!
//! Instead of bundling full contract ABIs from JSON artifacts, this module
//! defines only the functions, events, errors, and structs that the ciphernode
//! actually uses.  Contract upgrades must keep these exact signatures stable.
//!
//! All contract types (interfaces, enums) are replaced with their ABI-level
//! counterparts: `address` for contract types, `uint8` for enums.

use alloy::sol;

// ── IInterfold ───────────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IInterfold {
        struct E3 {
            uint256 seed;
            uint8 committeeSize;
            uint256 requestBlock;
            uint256[2] inputWindow;
            bytes32 encryptionSchemeId;
            address e3Program;
            uint8 paramSet;
            bytes customParams;
            address decryptionVerifier;
            address pkVerifier;
            bytes32 committeePublicKey;
            bytes32 ciphertextOutput;
            bytes plaintextOutput;
            address requester;
            bytes32 ciphertextCommitment;
        }

        struct E3Deadlines {
            uint256 dkgDeadline;
            uint256 computeDeadline;
            uint256 decryptionDeadline;
        }

        struct E3TimeoutConfig {
            uint256 dkgWindow;
            uint256 computeWindow;
            uint256 decryptionWindow;
        }

        // ── Write functions ─────────────────────────────────────────────────
        function publishPlaintextOutput(
            uint256 e3Id,
            bytes calldata plaintextOutput,
            bytes calldata proof
        ) external returns (bool success);

        function processE3Failure(uint256 e3Id) external;

        function markE3Failed(uint256 e3Id) external returns (uint8 reason);

        // ── View functions ──────────────────────────────────────────────────
        function getE3(uint256 e3Id) external view returns (E3 memory e3);

        function getE3Stage(uint256 e3Id) external view returns (uint8 stage);

        function getFailureReason(uint256 e3Id) external view returns (uint8 reason);

        function getDeadlines(uint256 e3Id) external view returns (E3Deadlines memory deadlines);

        function getE3TimeoutConfig(
            uint256 e3Id
        ) external view returns (E3TimeoutConfig memory config);

        function checkFailureCondition(
            uint256 e3Id
        ) external view returns (bool canFail, uint8 reason);

        function markFailedGracePeriod() external view returns (uint256);

        function nodeReleaseRegistry() external view returns (address);
        function bondingRegistry() external view returns (address);
        function ciphernodeRegistry() external view returns (address);

        // ── Events ──────────────────────────────────────────────────────────
        event E3Requested(uint256 e3Id, E3 e3, bytes32 indexed cryptoConfigId);
        event InputPublished(uint256 indexed e3Id, bytes data, uint256 inputHash, uint256 index);
        event CiphertextOutputPublished(uint256 indexed e3Id, bytes ciphertextOutput, bytes32 ciphertextCommitment);
        event CiphertextOutputReferencePublished(
            uint256 indexed e3Id,
            bytes32 contentHash,
            bytes32 ciphertextCommitment,
            uint32 availabilityBlock,
            uint128 availabilityLeafIndex
        );
        event PlaintextOutputPublished(uint256 indexed e3Id, bytes plaintextOutput, bytes proof);
        event RewardsDistributed(uint256 indexed e3Id, address[] nodes, uint256[] amounts);
        event RewardCredited(uint256 indexed e3Id, address indexed account, address indexed token, uint256 amount);
        event RewardClaimed(uint256 indexed e3Id, address indexed account, address indexed token, uint256 amount);
        event E3Failed(uint256 indexed e3Id, uint8 failedAtStage, uint8 reason);
        event E3StageChanged(uint256 indexed e3Id, uint8 previousStage, uint8 newStage);

        // ── Errors (only those our called functions can revert with) ────────
        error CiphertextOutputNotPublished(uint256 e3Id);
        error PlaintextOutputAlreadyPublished(uint256 e3Id);
        error E3DoesNotExist(uint256 e3Id);
        error InvalidStage(uint256 e3Id, uint8 expected, uint8 actual);
        error ProofRequired();
        error InvalidOutput(bytes output);
        error E3NotFailed(uint256 e3Id);
        error NoPaymentToRefund(uint256 e3Id);
        error FailureConditionNotMet(uint256 e3Id);
        error E3AlreadyFailed(uint256 e3Id);
        error E3AlreadyComplete(uint256 e3Id);
        error MarkE3FailedInGracePeriod(uint256 e3Id, uint256 gracePeriodEnds);
        error DKGDeadlinePassed(uint256 e3Id, uint256 deadline);
    }
}

// ── INodeReleaseRegistry ───────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface INodeReleaseRegistry {
        struct OperatorNodeRelease {
            bytes32 releaseId;
            uint32 protocolVersion;
            uint32 nodeGeneration;
        }

        function acknowledgeNodeRelease(bytes32 releaseId, uint32 protocolVersion, uint32 nodeGeneration) external;
        function requiredProtocolVersion() external view returns (uint32);
        function requiredNodeGeneration() external view returns (uint32);
        function operatorNodeRelease(address operator) external view returns (OperatorNodeRelease memory);
        function bondingRegistry() external view returns (address);
        function ciphernodeRegistry() external view returns (address);
    }
}

// ── ISlashingManager ────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface ISlashingManager {
        struct SlashPolicy {
            uint256 ticketPenalty;
            uint256 ciphernodeBondPenalty;
            bool requiresProof;
            address proofVerifier;
            bool banNode;
            uint256 appealWindow;
            bool enabled;
            bool affectsCommittee;
            uint8 failureReason;
        }

        // ── Write functions ─────────────────────────────────────────────────
        function proposeSlash(
            uint256 e3Id,
            address operator,
            bytes calldata proof
        ) external returns (uint256 proposalId);

        function proposeSlashByDkgParty(
            uint256 e3Id,
            uint256 partyId,
            bytes calldata proof
        ) external returns (uint256 proposalId);

        // ── View functions ──────────────────────────────────────────────────
        function ciphernodeRegistry() external view returns (address);

        function getSlashPolicy(bytes32 reason) external view returns (SlashPolicy memory policy);

        // ── Events ──────────────────────────────────────────────────────────
        event SlashExecuted(
            uint256 indexed proposalId,
            uint256 e3Id,
            address indexed operator,
            bytes32 indexed reason,
            uint256 ticketAmount,
            uint256 ciphernodeBondAmount,
            bool executed,
            uint8 lane
        );

        // ── Errors (only those our called functions can revert with) ────────
        error OperatorNotInCommittee();
        error VoterNotInCommittee();
        error DuplicateEvidence();
        error InsufficientAttestations();
        error InvalidVoteSignature();
        error SignatureExpired();
        error DuplicateVoter();
        error VoterIsAccused();
        error EquivocationDetected();
        error ChainIdMismatch();
        error PartyIdNotInDkgAnchors();
        error ProofRequired();
        error InvalidProof();
        error Unauthorized();
    }
}

// ── ICiphernodeRegistry ────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface ICiphernodeRegistry {
        // ── Write functions ─────────────────────────────────────────────────
        function submitTicket(uint256 e3Id, uint256 ticketNumber) external;

        function finalizeCommittee(uint256 e3Id) external returns (bool success);

        function publishCommittee(
            uint256 e3Id,
            bytes32 pkCommitment,
            bytes calldata proof,
            bytes calldata dkgAttestationBundle
        ) external;

        // ── View functions ──────────────────────────────────────────────────
        function isOpen(uint256 e3Id) external view returns (bool);

        function committeeThresholdMet(uint256 e3Id) external view returns (bool);

        function getCommitteeDeadline(uint256 e3Id) external view returns (uint256);

        function committeePublicKey(uint256 e3Id) external view returns (bytes32 publicKeyHash);

        function getDkgAnchors(
            uint256 e3Id
        )
            external
            view
            returns (
                uint256[] memory partyIds,
                bytes32[] memory skAggCommits,
                bytes32[] memory esmAggCommits
            );

        function canonicalCommitteeNodeAt(
            uint256 e3Id,
            uint256 partyId
        ) external view returns (address);

        function getActiveCommitteeNodes(
            uint256 e3Id
        ) external view returns (address[] memory nodes, uint256[] memory scores);

        function dkgFoldAttestationVerifier() external view returns (address);

        function accusationVoteValidity() external view returns (uint256);

        function numCiphernodes() external view returns (uint256);

        function randomnessProvider() external view returns (address);

        function sortitionSeed(
            uint256 e3Id
        ) external view returns (bool ready, uint256 seed);

        function getSortitionRequest(
            uint256 e3Id
        )
            external
            view
            returns (
                uint32[2] memory threshold,
                uint256 requestBlock,
                uint256 committeeDeadline,
                uint256 ticketPrice
            );

        // ── Events ──────────────────────────────────────────────────────────
        event CiphernodeAdded(
            address indexed node,
            uint256 index,
            uint256 numNodes,
            uint256 size
        );

        event CiphernodeRemoved(
            address indexed node,
            uint256 index,
            uint256 numNodes,
            uint256 size
        );

        event CommitteeRequested(
            uint256 indexed e3Id,
            uint256 entropyBlock,
            uint32[2] threshold,
            uint256 requestBlock,
            uint256 committeeDeadline,
            uint256 ticketPrice
        );

        event CommitteeRandomnessRequested(
            uint256 indexed e3Id,
            uint256 indexed requestId,
            address indexed provider,
            uint256 randomnessDeadline
        );

        event RandomnessProviderSet(address indexed randomnessProvider);

        event RandomnessCircuitBreakerTripped(
            uint256 indexed e3Id,
            uint256 indexed requestId,
            address indexed randomnessProvider
        );

        event RandomnessRequestTimeoutSet(uint256 randomnessRequestTimeout);

        event SortitionCommitteeFinalized(
            uint256 indexed e3Id,
            address[] committee,
            uint256[] scores
        );

        event DkgFoldAttestationContextEstablished(
            uint256 indexed e3Id,
            address indexed registry,
            address indexed dkgFoldAttestationVerifier
        );

        event CommitteeFormationFailed(
            uint256 indexed e3Id,
            uint256 nodesSubmitted,
            uint256 thresholdRequired
        );

        event CommitteeProofPublished(
            uint256 indexed e3Id,
            address[] nodes,
            bytes32 pkCommitment,
            bytes proof
        );

        event CommitteePublished(
            uint256 indexed e3Id,
            address[] nodes,
            bytes publicKey,
            bytes32 pkCommitment,
            bytes proof
        );

        event CommitteePublicKeyChunkPublished(
            uint256 indexed e3Id,
            address indexed publisher,
            bytes32 indexed candidateHash,
            address[] nodes,
            bytes32 pkCommitment,
            uint16 chunkIndex,
            uint16 chunkCount,
            uint32 totalLength,
            bytes chunk
        );

        event CommitteeActivationChanged(uint256 indexed e3Id, bool active);

        event CommitteeViabilityUpdated(
            uint256 indexed e3Id,
            uint256 activeCount,
            uint256 thresholdM,
            bool viable
        );

        event TicketSubmitted(
            uint256 indexed e3Id,
            address indexed node,
            uint256 ticketId,
            uint256 score
        );

        event CommitteeMemberExpelled(
            uint256 indexed e3Id,
            address indexed node,
            bytes32 reason,
            uint256 activeCountAfter
        );

        // ── Errors (only those our called functions can revert with) ────────
        error CommitteeNotRequested();
        error CommitteeAlreadyFinalized();
        error CommitteeNotFinalized();
        error CommitteeNotPublished();
        error CommitteeAlreadyPublished();
        error SubmissionWindowClosed();
        error SubmissionWindowNotClosed();
        error ThresholdNotMet();
        error NodeAlreadySubmitted();
        error CommitteeDeadlineReached();
        error InvalidTicketNumber();
        error NodeNotEligible();
        error PkCommitmentRequired();
        error DkgProofRequired();
        error InvalidDkgProof();
        error FoldAttestationsRequired();
        error FoldAttestationVerifierNotSet();
        error InvalidFoldAttestation();
        error PartyIdNotInProof();
        error AttestationBindingCountMismatch();
        error PartyIdOutOfBounds(uint256 partyId, uint256 committeeSize);
        error InvalidProof();
        error InvalidPublicInputsLength();
        error VkHashMismatch();
        error PkCommitmentMismatch();
        error DomainBindingMismatch();
        error InvalidPublicKeyLength(uint256 supplied, uint256 maximum);
        error InvalidPublicKeyChunk();
        error PublicKeyPublisherNotCommitteeMember();
    }
}

// ── IRandomnessProvider ────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IRandomnessProvider {
        event RandomnessFulfilled(
            uint256 indexed requestId,
            uint256 indexed e3Id,
            uint256 randomWord,
            uint256 fulfilledAt
        );
    }
}

// ── IBondingRegistry ────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IBondingRegistry {
        function getTicketBalance(address operator) external view returns (uint256);
        function getCiphernodeBond(address operator) external view returns (uint256);
        function bondOwnerOf(address operator) external view returns (address);
        function availableTickets(address operator) external view returns (uint256);
        function isRegistered(address operator) external view returns (bool);
        function isActive(address operator) external view returns (bool);
        function numActiveOperators() external view returns (uint256);
        function hasExitInProgress(address operator) external view returns (bool);

        event TicketBalanceUpdated(
            address indexed operator,
            int256 delta,
            uint256 newBalance,
            bytes32 indexed reason
        );

        event CiphernodeBondUpdated(
            address indexed operator,
            int256 delta,
            uint256 newBond,
            bytes32 indexed reason
        );

        event CiphernodeDeregistrationRequested(address indexed operator, uint64 unlockAt);

        event OperatorActivationChanged(address indexed operator, bool active);

        event BondOwnerSet(address indexed operator, address indexed bondOwner);

        event ConfigurationUpdated(
            bytes32 indexed parameter,
            uint256 oldValue,
            uint256 newValue
        );
    }
}
