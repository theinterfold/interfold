// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IInterfold } from "./IInterfold.sol";
import { IBondingRegistry } from "./IBondingRegistry.sol";

/**
 * @title ICiphernodeRegistry
 * @notice Interface for managing ciphernode registration and committee selection
 * @dev This registry maintains an Incremental Merkle Tree (IMT) of registered ciphernodes
 * and coordinates committee selection for E3 computations
 */
interface ICiphernodeRegistry {
    /// @notice Tracks a committee member's lifecycle state for a given E3.
    enum MemberStatus {
        None,
        Active,
        Expelled
    }

    /// @notice Lifecycle stage of a committee for a given E3.
    enum CommitteeStage {
        None,
        Requested,
        Finalized,
        Failed
    }

    /// @notice Struct representing the sortition state for an E3 round.
    /// @param stage Current lifecycle stage of the committee (replaces former initialized/finalized/failed bools).
    /// @param requestBlock The block number when the committee was requested.
    /// @param committeeDeadline The deadline for committee formation (ticket submission).
    /// @param threshold The M/N threshold for the committee ([M, N]).
    /// @param publicKey Hash of the committee's public key.
    /// @param seed The seed for the round.
    /// @param topNodes Sorted top-N nodes selected during sortition.
    /// @param committeeHash `keccak256(abi.encodePacked(topNodes))`, set at publication.
    /// @param submitted Mapping of nodes to their submission status.
    /// @param scoreOf Mapping of nodes to their scores.
    /// @param memberStatus Tri-state membership tracking (None / Active / Expelled).
    struct Committee {
        CommitteeStage stage;
        uint256 seed;
        uint256 requestBlock;
        uint256 committeeDeadline;
        bytes32 publicKey;
        uint32[2] threshold;
        address[] topNodes;
        bytes32 committeeHash;
        mapping(address node => bool submitted) submitted;
        mapping(address node => uint256 score) scoreOf;
        mapping(address node => MemberStatus) memberStatus;
        uint256 activeCount;
    }

    /// @notice This event MUST be emitted when a committee is selected for an E3.
    /// @param e3Id ID of the E3 for which the committee was selected.
    /// @param seed Random seed for score computation.
    /// @param threshold The M/N threshold for the committee.
    /// @param requestBlock Block number for snapshot validation.
    /// @param committeeDeadline Deadline for committee formation (ticket submission).
    event CommitteeRequested(
        uint256 indexed e3Id,
        uint256 seed,
        uint32[2] threshold,
        uint256 requestBlock,
        uint256 committeeDeadline
    );

    /// @notice This event MUST be emitted when a ticket is submitted for sortition
    /// @param e3Id ID of the E3 computation
    /// @param node Address of the ciphernode submitting the ticket
    /// @param ticketId The ticket number being submitted
    /// @param score The computed score for the ticket
    event TicketSubmitted(
        uint256 indexed e3Id,
        address indexed node,
        uint256 ticketId,
        uint256 score
    );

    /// @notice This event MUST be emitted when a committee is finalized
    /// @param e3Id ID of the E3 computation
    /// @param committee Array of selected ciphernode addresses
    /// @param scores Array of sortition scores corresponding to each committee member
    /// @notice MUST be emitted when sortition selects a committee for an E3.
    /// @dev Renamed from `CommitteeFinalized` to avoid clashing with the
    ///      canonical {IInterfold.CommitteeFinalized} surface.
    /// @param e3Id ID of the E3 computation
    /// @param committee Array of selected ciphernode addresses
    /// @param scores Array of sortition scores corresponding to each committee member
    event SortitionCommitteeFinalized(
        uint256 indexed e3Id,
        address[] committee,
        uint256[] scores
    );

    /// @notice This event MUST be emitted when committee formation fails (threshold not met)
    /// @param e3Id ID of the E3 computation
    /// @param nodesSubmitted Number of nodes that submitted tickets
    /// @param thresholdRequired Minimum number of nodes required
    event CommitteeFormationFailed(
        uint256 indexed e3Id,
        uint256 nodesSubmitted,
        uint256 thresholdRequired
    );

    /// @notice This event MUST be emitted when a committee is selected for an E3.
    /// @param e3Id ID of the E3 for which the committee was selected.
    /// @param publicKey Public key of the committee.
    /// @param pkCommitment Hash-based aggregated PK commitment for the committee.
    /// @param proof DkgAggregator (EVM) proof bytes verified prior to publication,
    ///              or empty bytes when proof aggregation is disabled for the E3.
    event CommitteePublished(
        uint256 indexed e3Id,
        address[] nodes,
        bytes publicKey,
        bytes32 pkCommitment,
        bytes proof
    );

    /// @notice This event MUST be emitted when a committee's active status changes.
    /// @param e3Id ID of the E3 for which the committee status changed.
    /// @param active True if committee is now active, false if completed.
    event CommitteeActivationChanged(uint256 indexed e3Id, bool active);

    /// @notice This event MUST be emitted when a committee member is expelled due to slashing.
    /// @param e3Id ID of the E3 for which the member was expelled.
    /// @param node Address of the expelled committee member.
    /// @param reason Hash of the slash reason that caused the expulsion.
    /// @param activeCountAfter Number of active committee members remaining after expulsion.
    event CommitteeMemberExpelled(
        uint256 indexed e3Id,
        address indexed node,
        bytes32 reason,
        uint256 activeCountAfter
    );

    /// @notice This event MUST be emitted when committee viability changes after an expulsion.
    /// @param e3Id ID of the E3.
    /// @param activeCount Current number of active committee members.
    /// @param thresholdM The minimum threshold (M) required.
    /// @param viable Whether the committee is still viable (activeCount >= M).
    event CommitteeViabilityUpdated(
        uint256 indexed e3Id,
        uint256 activeCount,
        uint256 thresholdM,
        bool viable
    );

    /// @notice This event MUST be emitted when `interfold` is set.
    /// @param interfold Address of the interfold contract.
    event InterfoldSet(address indexed interfold);

    /// @notice Emitted when the owner proposes a new DKG fold-attestation verifier.
    /// @dev The new verifier becomes active only after `commitDkgFoldAttestationVerifier`
    ///      is called and at least `DKG_FOLD_VERIFIER_TIMELOCK` has elapsed.
    event DkgFoldAttestationVerifierProposed(
        address indexed verifier,
        uint256 readyAt
    );

    /// @notice Emitted when the proposed DKG fold-attestation verifier becomes active.
    event DkgFoldAttestationVerifierUpdated(address indexed verifier);

    /// @notice Emitted when the owner cancels a pending verifier proposal.
    event DkgFoldAttestationVerifierProposalCancelled(address indexed verifier);

    /// @notice This event MUST be emitted when a ciphernode is added to the registry.
    /// @param node Address of the ciphernode.
    /// @param index Index of the ciphernode in the registry.
    /// @param numNodes Number of ciphernodes in the registry.
    /// @param size Size of the registry.
    event CiphernodeAdded(
        address indexed node,
        uint256 index,
        uint256 numNodes,
        uint256 size
    );

    /// @notice This event MUST be emitted when a ciphernode is removed from the registry.
    /// @param node Address of the ciphernode.
    /// @param index Index of the ciphernode in the registry.
    /// @param numNodes Number of ciphernodes in the registry.
    /// @param size Size of the registry.
    event CiphernodeRemoved(
        address indexed node,
        uint256 index,
        uint256 numNodes,
        uint256 size
    );

    /// @notice This event MUST be emitted any time the `sortitionSubmissionWindow` is set.
    /// @param sortitionSubmissionWindow The submission window for the E3 sortition in seconds.
    event SortitionSubmissionWindowSet(uint256 sortitionSubmissionWindow);

    /// @notice Emitted whenever the registry-wide accusation vote validity window changes.
    /// @param accusationVoteValidity New validity window, in seconds.
    event AccusationVoteValiditySet(uint256 accusationVoteValidity);

    /// @notice Emitted when the owner proposes a new accusation vote validity value.
    /// @param accusationVoteValidity Pending validity window, in seconds.
    /// @param readyAt Earliest timestamp when commit is allowed.
    event AccusationVoteValidityProposed(
        uint256 accusationVoteValidity,
        uint256 readyAt
    );

    /// @notice Emitted when the owner cancels a pending accusation vote validity proposal.
    /// @param accusationVoteValidity Pending value that was cancelled.
    event AccusationVoteValidityProposalCancelled(
        uint256 accusationVoteValidity
    );

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                        Errors                          //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Committee has already been requested for this E3
    error CommitteeAlreadyRequested();

    /// @notice Committee has already been published for this E3
    error CommitteeAlreadyPublished();

    /// @notice Committee has not been published yet for this E3
    error CommitteeNotPublished();

    /// @notice Committee has not been requested yet for this E3
    error CommitteeNotRequested();

    /// @notice Committee Not Initialized or Finalized
    error CommitteeNotInitializedOrFinalized();

    /// @notice Submission Window has been closed for this E3
    error SubmissionWindowClosed();

    /// @notice Committee deadline has been reached for this E3
    error CommitteeDeadlineReached();

    /// @notice Committee has already been finalized for this E3
    error CommitteeAlreadyFinalized();

    /// @notice Committee has not been finalized yet for this E3
    error CommitteeNotFinalized();

    /// @notice `publishCommittee` requires a non-zero PK commitment
    error PkCommitmentRequired();

    /// @notice Proof aggregation is enabled but no DKG proof was supplied
    error DkgProofRequired();

    /// @notice Supplied DKG aggregator proof failed verification
    error InvalidDkgProof();

    /// @notice Proof aggregation enabled but no fold attestation bundle was supplied
    error FoldAttestationsRequired();

    /// @notice `dkgFoldAttestationVerifier` is not configured on the registry
    error FoldAttestationVerifierNotSet();

    /// @notice Initial verifier set was attempted after one was already configured.
    /// @dev Subsequent changes must go through `proposeDkgFoldAttestationVerifier` →
    ///      `commitDkgFoldAttestationVerifier` (timelocked).
    error FoldAttestationVerifierAlreadySet();

    /// @notice Fold attestation bundle failed signature or public-input binding checks
    error InvalidFoldAttestation();

    /// @notice `partyId` from an attestation does not appear in the DKG proof public inputs
    error PartyIdNotInProof();

    /// @notice Attestation count does not match bindings or proof honest-set size
    error AttestationBindingCountMismatch();

    /// @notice `partyId` is out of bounds for the finalized committee's `topNodes`
    error PartyIdOutOfBounds(uint256 partyId, uint256 committeeSize);

    /// @notice A `setDkgFoldAttestationVerifier` commit was attempted before the timelock elapsed.
    error VerifierUpdateTimelockActive(uint256 readyAt, uint256 nowAt);

    /// @notice `commitDkgFoldAttestationVerifier` was called but no proposal is pending.
    error NoPendingVerifierUpdate();

    /// @notice `commitDkgFoldAttestationVerifier` was called with an address that does
    /// not match the pending proposal (prevents commit-time substitution).
    error VerifierMismatch(address pending, address provided);

    /// @notice A vote-validity commit was attempted before timelock elapsed.
    error AccusationVoteValidityTimelockActive(uint256 readyAt, uint256 nowAt);

    /// @notice `commitAccusationVoteValidity` was called but no proposal is pending.
    error NoPendingAccusationVoteValidityUpdate();

    /// @notice `commitAccusationVoteValidity` was called with value that does not match pending.
    error AccusationVoteValidityMismatch(uint256 pending, uint256 provided);

    /// @notice Directly setting `accusationVoteValidity` to zero is disallowed.
    ///         Use `proposeAccusationVoteValidity` + `commitAccusationVoteValidity`.
    error AccusationVoteValidityZeroRequiresTimelock();

    /// @notice Node has already submitted a ticket for this E3
    error NodeAlreadySubmitted();

    /// @notice Node has not submitted a ticket for this E3
    error NodeNotSubmitted();

    /// @notice Node is not eligible for this E3
    error NodeNotEligible();

    /// @notice Ciphernode is not enabled in the registry
    /// @param node Address of the ciphernode
    error CiphernodeNotEnabled(address node);

    /// @notice Caller is not the Interfold contract
    error OnlyInterfold();

    /// @notice Caller is not the bonding registry
    error OnlyBondingRegistry();

    /// @notice Caller is neither owner nor bonding registry
    error NotOwnerOrBondingRegistry();

    /// @notice Node is not bonded
    /// @param node Address of the node
    error NodeNotBonded(address node);

    /// @notice Address cannot be zero
    error ZeroAddress();

    /// @notice Bonding registry has not been set
    error BondingRegistryNotSet();

    /// @notice Invalid ticket number
    error InvalidTicketNumber();

    /// @notice Submission window not closed yet
    error SubmissionWindowNotClosed();

    /// @notice Threshold not met for this E3
    error ThresholdNotMet();

    /// @notice Caller is not authorized
    error Unauthorized();

    /// @notice Caller is not the slashing manager
    error NotSlashingManager();

    /// @notice Not enough registered ciphernodes to meet threshold
    /// @param requested The requested committee size (N)
    /// @param available The number of registered ciphernodes
    error InsufficientCiphernodes(uint256 requested, uint256 available);

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                  Function Signatures                   //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Check if a ciphernode is eligible for committee selection
    /// @dev A ciphernode is eligible if it is enabled in the registry and meets bonding requirements
    /// @param ciphernode Address of the ciphernode to check
    /// @return eligible Whether the ciphernode is eligible for committee selection
    function isCiphernodeEligible(address ciphernode) external returns (bool);

    /// @notice Check if a ciphernode is enabled in the registry
    /// @param node Address of the ciphernode
    /// @return enabled Whether the ciphernode is enabled
    function isEnabled(address node) external view returns (bool enabled);

    /// @notice Add a ciphernode to the registry
    /// @param node Address of the ciphernode to add
    function addCiphernode(address node) external;

    /// @notice Remove a ciphernode from the registry
    /// @param node Address of the ciphernode to remove
    function removeCiphernode(address node) external;

    /// @notice Initiates the committee selection process for a specified E3.
    /// @dev This function MUST revert when not called by the Interfold contract.
    /// @param e3Id ID of the E3 for which to select the committee.
    /// @param seed Random seed for score computation.
    /// @param threshold The M/N threshold for the committee.
    /// @return success True if committee selection was successfully initiated.
    function requestCommittee(
        uint256 e3Id,
        uint256 seed,
        uint32[2] calldata threshold
    ) external returns (bool success);

    /// @notice Publishes the public key resulting from the committee selection process.
    /// @dev Permissionless once the committee is finalized.
    ///      When `e3.proofAggregationEnabled` is true, the `proof` is verified against
    ///      `pkCommitment` via the E3's pk verifier. When disabled, `proof` may be empty
    ///      and `pkCommitment` is trusted from the (signed) aggregator.
    /// @param e3Id ID of the E3 for which to select the committee.
    /// @param publicKey The public key generated by the given committee.
    /// @param pkCommitment Hash-based aggregated PK commitment for the committee.
    /// @param proof DkgAggregator (EVM) proof ABI-encoded `(bytes rawProof, bytes32[] publicInputs)`,
    ///              or empty bytes when proof aggregation is disabled.
    /// @param dkgAttestationBundle ABI-encoded
    ///        `(DkgFoldAttestationLib.Attestation[] attestations, DkgFoldAttestationLib.PartySlotBinding[] bindings)`.
    ///        Required (non-empty) when proof aggregation is enabled; ignored otherwise.
    function publishCommittee(
        uint256 e3Id,
        bytes calldata publicKey,
        bytes32 pkCommitment,
        bytes calldata proof,
        bytes calldata dkgAttestationBundle
    ) external;

    /// @notice Returns DKG anchor commitments stored at publication (empty if not yet published).
    /// @param e3Id ID of the E3
    /// @return partyIds Honest party ids (same order as stored sk/esm arrays)
    /// @return skAggCommits Per-party secret-key aggregate commitments from NodeFold
    /// @return esmAggCommits Per-party smudging-noise aggregate commitments from NodeFold
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

    /// @notice This function should be called by the Interfold contract to get the public key of a committee.
    /// @dev This function MUST revert if no committee has been requested for the given E3.
    /// @dev This function MUST revert if the committee has not yet published a public key.
    /// @param e3Id ID of the E3 for which to get the committee public key.
    /// @return publicKeyHash The hash of the public key of the given committee.
    function committeePublicKey(
        uint256 e3Id
    ) external view returns (bytes32 publicKeyHash);

    /// @notice This function should be called by the Interfold contract to get the committee for a given E3.
    /// @dev This function MUST revert if no committee has been requested for the given E3.
    /// @param e3Id ID of the E3 for which to get the committee.
    /// @return committeeNodes The nodes in the committee for the given E3.
    function getCommitteeNodes(
        uint256 e3Id
    ) external view returns (address[] memory committeeNodes);

    /// @notice Returns the committee hash cached at `publishCommittee` time.
    /// @param e3Id ID of the E3
    /// @return committeeHash `keccak256(abi.encodePacked(topNodes))` for the published committee
    function getCommitteeHash(
        uint256 e3Id
    ) external view returns (bytes32 committeeHash);

    /// @notice Returns the current root of the ciphernode IMT
    /// @return Current IMT root
    function root() external view returns (uint256);

    /// @notice Returns the IMT root at the time a committee was requested
    /// @param e3Id ID of the E3
    /// @return IMT root at time of committee request
    function rootAt(uint256 e3Id) external view returns (uint256);

    /// @notice Returns the current size of the ciphernode IMT
    /// @return Size of the IMT
    function treeSize() external view returns (uint256);

    /// @notice Returns the address of the bonding registry
    /// @return Address of the bonding registry contract
    function getBondingRegistry() external view returns (address);

    /// @notice Sets the Interfold contract address
    /// @dev Only callable by owner
    /// @param _interfold Address of the Interfold contract
    function setInterfold(IInterfold _interfold) external;

    /// @notice Sets the bonding registry contract address
    /// @dev Only callable by owner
    /// @param _bondingRegistry Address of the bonding registry contract
    function setBondingRegistry(IBondingRegistry _bondingRegistry) external;

    /// @notice Returns the current sortition submission window.
    /// @return The sortition submission window in seconds.
    function sortitionSubmissionWindow() external view returns (uint256);

    /// @notice This function should be called to set the submission window for the E3 sortition.
    /// @param _sortitionSubmissionWindow The submission window for the E3 sortition in seconds.
    function setSortitionSubmissionWindow(
        uint256 _sortitionSubmissionWindow
    ) external;

    /// @notice Returns registry-wide accusation vote validity window (seconds).
    function accusationVoteValidity() external view returns (uint256);

    /// @notice Sets nonzero accusation vote validity directly.
    /// @dev Setting zero requires timelocked propose/commit flow.
    function setAccusationVoteValidity(
        uint256 _accusationVoteValidity
    ) external;

    /// @notice Propose accusation vote validity (supports zero).
    function proposeAccusationVoteValidity(
        uint256 _accusationVoteValidity
    ) external;

    /// @notice Commit accusation vote validity after timelock.
    function commitAccusationVoteValidity(
        uint256 _accusationVoteValidity
    ) external;

    /// @notice Cancel a pending accusation vote validity proposal.
    function cancelAccusationVoteValidityProposal() external;

    /// @notice Submit a ticket for sortition
    /// @dev Validates ticket against node's balance at request block
    /// @param e3Id ID of the E3 computation
    /// @param ticketNumber The ticket number to submit
    function submitTicket(uint256 e3Id, uint256 ticketNumber) external;

    /// @notice Finalize the committee after submission window closes
    /// @dev If threshold not met, marks E3 as failed and returns false
    /// @param e3Id ID of the E3 computation
    /// @return success True if committee formed successfully, false if threshold not met
    function finalizeCommittee(uint256 e3Id) external returns (bool success);

    /// @notice Check if submission window is still open for an E3
    /// @param e3Id ID of the E3 computation
    /// @return Whether the submission window is open
    function isOpen(uint256 e3Id) external view returns (bool);

    /// @notice Get the committee deadline for an E3
    /// @param e3Id ID of the E3 computation
    /// @return committeeDeadline The committee deadline timestamp
    function getCommitteeDeadline(uint256 e3Id) external view returns (uint256);

    /// @notice Expel a committee member from a specific E3 committee due to slashing
    /// @dev Only callable by SlashingManager. Idempotent (re-expelling same member is no-op).
    ///      Returns viability data so the caller can decide whether to fail the E3 —
    ///      eliminating the need for separate view calls to check count and threshold.
    /// @param e3Id ID of the E3 computation
    /// @param node Address of the committee member to expel
    /// @param reason Hash of the slash reason
    /// @return activeCount Number of active committee members after expulsion
    /// @return thresholdM The minimum threshold (M) required for viability
    function expelCommitteeMember(
        uint256 e3Id,
        address node,
        bytes32 reason
    ) external returns (uint256 activeCount, uint32 thresholdM);

    /// @notice Check if a committee member is still active for a specific E3
    /// @param e3Id ID of the E3 computation
    /// @param node Address of the committee member to check
    /// @return Whether the member is still active (not expelled) in the committee
    function isCommitteeMemberActive(
        uint256 e3Id,
        address node
    ) external view returns (bool);

    /// @notice Check if an address was ever a committee member for a specific E3
    /// @param e3Id ID of the E3 computation
    /// @param node Address to check
    /// @return Whether the address was ever a member of the finalized committee
    function isCommitteeMember(
        uint256 e3Id,
        address node
    ) external view returns (bool);

    /// @notice Return the operator address at slot `partyId` in the finalized
    ///         committee's `topNodes` (address-ascending order).
    /// @dev Unlike `getCommitteeNodes`, this does NOT require the committee to
    ///      be published yet — it works as soon as the committee is finalized,
    ///      which is what `publishCommittee` callers need in order to bind a
    ///      `partyId` to a specific operator before the public key is stored.
    ///      Reverts `CommitteeNotFinalized` for non-finalized committees so the
    ///      provisional, sortition-in-progress `topNodes` is never exposed.
    /// @param e3Id ID of the E3 computation
    /// @param partyId Index into `topNodes`
    /// @return Operator address at `topNodes[partyId]`
    function canonicalCommitteeNodeAt(
        uint256 e3Id,
        uint256 partyId
    ) external view returns (address);

    /// @notice Get active (non-expelled) committee nodes for an E3
    /// @param e3Id ID of the E3 computation
    /// @return nodes Array of active committee member addresses
    /// @return scores Array of active committee member ticket scores aligned with `nodes`
    function getActiveCommitteeNodes(
        uint256 e3Id
    ) external view returns (address[] memory nodes, uint256[] memory scores);

    /// @notice Consolidated committee viability check — avoids two separate view calls.
    /// @param e3Id ID of the E3 computation
    /// @return activeCount Current number of active (non-expelled) committee members
    /// @return thresholdM Minimum required members (M in M-of-N)
    /// @return thresholdN Total desired committee size (N in M-of-N)
    /// @return viable True when activeCount >= thresholdM
    function getCommitteeViability(
        uint256 e3Id
    )
        external
        view
        returns (
            uint256 activeCount,
            uint32 thresholdM,
            uint32 thresholdN,
            bool viable
        );
}
