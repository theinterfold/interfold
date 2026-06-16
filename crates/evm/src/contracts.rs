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
            bool proofAggregationEnabled;
        }

        // ── Write functions ─────────────────────────────────────────────────
        function publishPlaintextOutput(
            uint256 e3Id,
            bytes calldata plaintextOutput,
            bytes calldata proof
        ) external returns (bool success);

        function processE3Failure(uint256 e3Id) external;

        // ── View functions ──────────────────────────────────────────────────
        function getE3(uint256 e3Id) external view returns (E3 memory e3);

        // ── Events ──────────────────────────────────────────────────────────
        event E3Requested(uint256 e3Id, E3 e3, address indexed e3Program);
        event CiphertextOutputPublished(uint256 indexed e3Id, bytes ciphertextOutput);
        event E3Failed(uint256 e3Id, uint8 failedAtStage, uint8 reason);
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
    }
}

// ── ISlashingManager ────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface ISlashingManager {
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

        // ── Events ──────────────────────────────────────────────────────────
        event SlashExecuted(
            uint256 proposalId,
            uint256 e3Id,
            address operator,
            bytes32 reason,
            uint256 ticketAmount,
            uint256 licenseAmount
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
            bytes calldata publicKey,
            bytes32 pkCommitment,
            bytes calldata proof,
            bytes calldata dkgAttestationBundle
        ) external;

        // ── View functions ──────────────────────────────────────────────────
        function isOpen(uint256 e3Id) external view returns (bool);

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

        function dkgFoldAttestationVerifier() external view returns (address);

        function accusationVoteValidity() external view returns (uint256);

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
            uint256 seed,
            uint32[2] threshold,
            uint256 requestBlock,
            uint256 committeeDeadline
        );

        event SortitionCommitteeFinalized(
            uint256 indexed e3Id,
            address[] committee,
            uint256[] scores
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
        error InvalidTicketNumber();
        error NodeNotEligible();
        error PkCommitmentRequired();
        error DkgProofRequired();
        error InvalidDkgProof();
        error FoldAttestationsRequired();
    }
}

// ── IBondingRegistry ────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IBondingRegistry {
        event TicketBalanceUpdated(
            address indexed operator,
            int256 delta,
            uint256 newBalance,
            bytes32 indexed reason
        );

        event OperatorActivationChanged(address indexed operator, bool active);

        event ConfigurationUpdated(
            bytes32 indexed parameter,
            uint256 oldValue,
            uint256 newValue
        );
    }
}
