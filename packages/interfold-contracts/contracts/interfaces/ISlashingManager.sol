// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { IBondingRegistry } from "./IBondingRegistry.sol";
import { ICiphernodeRegistry } from "./ICiphernodeRegistry.sol";
import { IE3RefundManager } from "./IE3RefundManager.sol";

/**
 * @title ISlashingManager
 * @notice Interface for managing slashing proposals, appeals, and execution
 * @dev Maintains policy table and handles slash workflows with two lanes:
 *      Lane A (proof-based): permissionless, atomic, no appeals
 *      Lane B (evidence-based): SLASHER_ROLE required, appeal window
 */
interface ISlashingManager {
    function activeE3Assignments() external view returns (uint256);

    function activeBanCount() external view returns (uint256);
    /// @notice API version required by BondingRegistry manager authorization.
    // solhint-disable-next-line func-name-mixedcase
    function SLASHING_MANAGER_API_VERSION() external view returns (uint256);

    // ======================
    // Enums
    // ======================

    /**
     * @notice Distinguishes the two slash lanes for event consumers and downstream
     *         consensus / accounting.
     * @dev Lane A is permissionless proof / attestation-based; Lane B is
     *      evidence-based and requires `SLASHER_ROLE`.
     */
    enum Lane {
        LaneA,
        LaneB
    }

    // ======================
    // Structs
    // ======================

    /**
     * @notice Slashing policy configuration for different slash reasons
     * @dev Defines penalties, proof requirements, and appeal mechanisms for each slash type
     * @param ticketPenalty Amount of ticket collateral to slash (in wei)
     * @param ciphernodeBondPenalty Amount of ciphernode bond to slash (in wei)
     * @param requiresProof Whether this slash type requires cryptographic proof verification
     * @param proofVerifier Optional ISlashVerifier for ZK-based slashes; Lane A (`proposeSlash`)
     *        uses on-chain attestation verification and may leave this as `address(0)`.
     * @param banNode Whether executing this slash will permanently ban the node
     * @param appealWindow Time window in seconds for operators to appeal (0 = immediate execution, no appeals)
     * @param enabled Whether this slash type is currently active and can be proposed
     * @param affectsCommittee Whether executing this slash triggers committee expulsion for the target E3
     * @param failureReason Reserved for storage and ABI compatibility. New policies use 0 or
     *        InsufficientCommitteeMembers.
     */
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

    /// @notice Bonding-asset identity used when a slash policy was configured.
    struct SlashPolicyAssetContext {
        address bondingRegistry;
        uint64 configurationVersion;
    }

    /**
     * @notice Slash proposal details tracking the full lifecycle of a slash
     * @dev Stores all state needed for proposal, appeal, and execution workflows
     * @param e3Id ID of the E3 computation this slash relates to
     * @param operator Address of the ciphernode operator being slashed
     * @param reason Hash of the slash reason (maps to SlashPolicy configuration)
     * @param ticketAmount Amount of ticket collateral to slash (copied from policy at proposal time)
     * @param ciphernodeBondAmount Amount of ciphernode bond to slash (copied from policy at proposal time)
     * @param executed Whether the slashing penalties have been executed
     * @param appealed Whether the operator has filed an appeal
     * @param resolved Whether the appeal has been resolved by governance
     * @param appealUpheld Whether the appeal was approved (true = cancel slash, false = slash proceeds)
     * @param proposedAt Block timestamp when the slash was proposed
     * @param executableAt Block timestamp when execution becomes possible (proposedAt + appealWindow)
     * @param proposer Address that created this slash proposal
     * @param proofHash Keccak256 hash of the proof data submitted with the proposal
     * @param proofVerified Whether the proof was successfully verified by the proof verifier contract
     */
    struct SlashProposal {
        uint256 e3Id;
        address operator;
        bytes32 reason;
        uint256 ticketAmount;
        uint256 ciphernodeBondAmount;
        bool executed;
        bool appealed;
        bool resolved;
        bool appealUpheld;
        uint256 proposedAt;
        uint256 executableAt;
        address proposer;
        bytes32 proofHash;
        bool proofVerified;
        /// @dev Snapshotted from SlashPolicy at proposal time to prevent execution drift
        bool banNode;
        /// @dev Snapshotted from SlashPolicy at proposal time to prevent execution drift
        bool affectsCommittee;
        /// @dev Reserved for storage and ABI compatibility. Committee viability loss uses a fixed reason.
        uint8 failureReason;
    }

    /// @notice Durable routing record for slashed ticket funds awaiting escrow.
    struct PendingSlashRoute {
        uint256 e3Id;
        address token;
        uint256 amount;
        bool pending;
        address operator;
    }

    // ======================
    // Errors
    // ======================

    /// @notice Thrown when a zero address is provided where a valid address is required
    error ZeroAddress();

    /// @notice Thrown when caller lacks required role permissions for the operation
    error Unauthorized();

    /// @notice Thrown when a slash policy configuration is invalid
    error InvalidPolicy();

    /// @notice A policy does not match the E3's bonding-asset configuration.
    error SlashPolicyAssetConfigurationMismatch(bytes32 reason);

    /// @notice Thrown when referencing a proposal ID that doesn't exist or is in invalid state
    error InvalidProposal();

    /// @notice Thrown when proof is required by policy but not provided
    error ProofRequired();

    /// @notice Thrown when provided proof fails verification
    error InvalidProof();

    /// @notice The ZK proof verified successfully — the operator's submission was valid, not a fault
    error ProofIsValid();

    /// @notice Thrown when the recovered signer does not match the operator being slashed
    error SignerIsNotOperator();

    /// @notice Thrown when the operator is not a member of the committee for this E3
    error OperatorNotInCommittee();

    /// @notice Thrown when a requested DKG `partyId` is not present in stored anchors for this E3
    error PartyIdNotInDkgAnchors();

    /// @notice Thrown when the verifier address in signed evidence doesn't match the policy's current verifier
    error VerifierMismatch();

    /// @notice Thrown when the verifier staticcall fails (e.g., contract doesn't exist, reverts, or runs out of gas)
    error VerifierCallFailed();

    /// @notice Thrown when attempting to execute a slash whose appeal was upheld
    error AppealUpheld();

    /// @notice Thrown when attempting to execute a slash with an unresolved appeal
    error AppealPending();

    /// @notice Thrown when attempting to file an appeal after the appeal window has closed
    error AppealWindowExpired();

    /// @notice Thrown when attempting to execute a slash before the appeal window has closed
    error AppealWindowActive();

    /// @notice Thrown when an unresolved appeal has not reached its terminal expiry.
    error AppealResolutionWindowActive();

    /// @notice Thrown when attempting to file a second appeal for the same proposal
    error AlreadyAppealed();

    /// @notice Thrown when attempting to execute a slash that has already been executed
    error AlreadyExecuted();

    /// @notice Thrown when attempting to resolve an appeal that has already been resolved
    error AlreadyResolved();

    /// @notice Thrown when referencing a slash reason that doesn't exist
    error SlashReasonNotFound();

    /// @notice Thrown when attempting to propose a slash for a disabled reason
    error SlashReasonDisabled();

    /// @notice Thrown when a banned ciphernode attempts a restricted operation
    error CiphernodeBanned();

    /// @notice Thrown when a policy requires proof but no verifier contract is configured
    error VerifierNotSet();

    /// @notice Thrown when the same evidence bundle has already been used in a proposal
    error DuplicateEvidence();

    /// @notice Thrown when the chainId in the signed proof payload does not match the current chain
    error ChainIdMismatch();

    /// @notice Thrown when the number of attestation votes is below the committee threshold M
    error InsufficientAttestations();

    /// @notice Thrown when the attestation voters array contains duplicate addresses (must be sorted ascending)
    error DuplicateVoter();

    /// @notice Thrown when an attestation voter is not a member of the committee for this E3
    error VoterNotInCommittee();

    /// @notice Thrown when an attestation vote signature does not recover to the declared voter
    error InvalidVoteSignature();

    /// @notice Thrown when the accused operator is included as a voter in the attestation
    error VoterIsAccused();

    /// @notice Thrown when attestation voters submit divergent dataHashes (equivocation)
    error EquivocationDetected();

    /// @notice Thrown when the attestation `deadline` has passed at the time of submission
    error SignatureExpired();

    /// @notice Lane A is disabled for the E3 or by the current live pause.
    error AccusationSlashingDisabled();

    /// @notice The signed accusation window is malformed or exceeds its snapshot.
    error InvalidAccusationWindow();

    /// @notice The signed issue time is too far ahead of the chain clock.
    error AccusationIssuedInFuture();

    /// @notice The objective E3 accusation reporting period has ended.
    error SlashSubmissionDeadlinePassed();
    error AccusationWindowOpen(uint256 e3Id, uint256 closesAt);

    /// @notice Thrown when an operator action is gated by any unresolved slash proposal
    error OperatorUnderSlash();

    /// @notice Thrown when a ban operation requires a distinct governance confirmer
    error BanRequiresConfirmation();

    /// @notice Thrown when no pending ban proposal exists for the target node
    error NoPendingBan();

    /// @notice The slash transaction did not leave enough gas for its bounded
    ///         initial routing attempt.
    error InsufficientRoutingGas();

    // ======================
    // Events
    // ======================

    /**
     * @notice Emitted when a slash policy is created or updated
     * @param reason Hash of the slash reason being configured
     * @param policy The complete policy configuration including penalties and appeal settings
     */
    event SlashPolicyUpdated(bytes32 indexed reason, SlashPolicy policy);

    /**
     * @notice Emitted when a new slash proposal is created
     * @param proposalId Unique ID of the created proposal
     * @param e3Id ID of the E3 computation related to this slash
     * @param operator Address of the ciphernode operator being slashed
     * @param reason Hash of the slash reason
     * @param ticketAmount Amount of ticket collateral to be slashed
     * @param ciphernodeBondAmount Amount of ciphernode bond to be slashed
     * @param executableAt Timestamp when the slash can be executed (after appeal window)
     * @param proposer Address that created the proposal
     */
    event SlashProposed(
        uint256 indexed proposalId,
        uint256 indexed e3Id,
        address indexed operator,
        bytes32 reason,
        uint256 ticketAmount,
        uint256 ciphernodeBondAmount,
        uint256 executableAt,
        address proposer,
        Lane lane
    );

    /**
     * @notice Emitted when a slash proposal is executed and penalties are applied
     * @param proposalId ID of the executed proposal
     * @param e3Id ID of the E3 committee associated with this slash
     * @param operator Address of the slashed operator
     * @param reason Hash of the slash reason
     * @param ticketAmount Amount of ticket collateral slashed
     * @param ciphernodeBondAmount Amount of ciphernode bond slashed
     * @param executed Execution status (should always be true)
     */
    event SlashExecuted(
        uint256 indexed proposalId,
        uint256 e3Id,
        address indexed operator,
        bytes32 indexed reason,
        uint256 ticketAmount,
        uint256 ciphernodeBondAmount,
        bool executed,
        Lane lane
    );

    /**
     * @notice Emitted when a node ban is proposed (two-step ban)
     * @param node Address being proposed for ban
     * @param reason Hash of the reason for the ban
     * @param proposer Governance address that initiated the proposal
     */
    event BanProposed(
        address indexed node,
        bytes32 indexed reason,
        address proposer
    );

    /**
     * @notice Emitted when a pending ban is cancelled before confirmation
     * @param node Address whose pending ban was cancelled
     * @param canceller Governance address that cancelled the proposal
     */
    event BanCancelled(address indexed node, address canceller);

    /**
     * @notice Emitted when an operator files an appeal against a slash proposal
     * @param proposalId ID of the proposal being appealed
     * @param operator Address of the operator filing the appeal
     * @param reason Hash of the slash reason being appealed
     * @param evidence Evidence string provided by the operator supporting their appeal
     */
    event AppealFiled(
        uint256 indexed proposalId,
        address indexed operator,
        bytes32 indexed reason,
        string evidence
    );

    /**
     * @notice Emitted when governance resolves an appeal
     * @param proposalId ID of the proposal with the resolved appeal
     * @param operator Address of the operator who appealed
     * @param appealUpheld Whether the appeal was approved (true = slash cancelled, false = slash proceeds)
     * @param resolver Address of the governance account that resolved the appeal
     * @param resolution Explanation string for the resolution decision
     */
    event AppealResolved(
        uint256 indexed proposalId,
        address indexed operator,
        bool appealUpheld,
        address resolver,
        string resolution
    );

    /**
     * @notice Emitted when a node is banned or unbanned from the network
     * @param node Address of the node
     * @param status Whether the node is banned
     * @param reason Hash of the reason for banning or unbanning
     * @param updater Address that executed the ban (governance or contract)
     */
    event NodeBanUpdated(
        address indexed node,
        bool status,
        bytes32 indexed reason,
        address updater
    );

    /**
     * @notice Emitted when slashed ticket funds are escrowed in the E3 refund pool
     * @param e3Id ID of the E3 computation
     * @param amount Amount of slashed funds escrowed (underlying stablecoin)
     */
    event SlashedFundsEscrowedToRefund(
        uint256 indexed e3Id,
        address indexed token,
        uint256 amount
    );

    /**
     * @notice Emitted when routing slashed funds fails (funds remain in BondingRegistry)
     * @param e3Id ID of the E3 computation
     * @param amount Amount that failed to route
     */
    event RoutingFailed(uint256 indexed e3Id, uint256 amount);

    /// @notice Emitted before a slash route is attempted and durably reserved.
    event SlashRoutePending(
        uint256 indexed proposalId,
        uint256 indexed e3Id,
        address indexed token,
        uint256 amount
    );

    /// @notice Emitted after a pending slash route reaches E3 escrow.
    event SlashRouteCompleted(
        uint256 indexed proposalId,
        uint256 indexed e3Id,
        address indexed token,
        uint256 amount
    );

    /// @notice Emitted after a terminal E3 releases its frozen dependencies.
    event E3DependenciesReleased(uint256 indexed e3Id);

    /**
     * @notice Emitted when the bonding registry is set
     * @param bondingRegistry Address of the bonding registry
     */
    event BondingRegistrySet(address indexed bondingRegistry);

    /**
     * @notice Emitted when the ciphernode registry is set
     * @param ciphernodeRegistry Address of the ciphernode registry
     */
    event CiphernodeRegistrySet(address indexed ciphernodeRegistry);

    /**
     * @notice Emitted when the Interfold contract is set
     * @param interfold Address of the Interfold contract
     */
    event InterfoldSet(address indexed interfold);

    /**
     * @notice Emitted when the E3 Refund Manager is set
     * @param e3RefundManager Address of the E3 Refund Manager
     */
    event E3RefundManagerSet(address indexed e3RefundManager);

    // ======================
    // View Functions
    // ======================

    /**
     * @notice Retrieves the slash policy configuration for a given reason
     * @param reason Hash of the slash reason to query
     * @return policy The complete SlashPolicy struct (returns default empty struct if not configured)
     */
    function getSlashPolicy(
        bytes32 reason
    ) external view returns (SlashPolicy memory policy);

    /**
     * @notice Retrieves the details of a slash proposal
     * @param proposalId ID of the proposal to query
     * @return proposal The complete SlashProposal struct
     * @dev Reverts with InvalidProposal if proposalId >= totalProposals
     */
    function getSlashProposal(
        uint256 proposalId
    ) external view returns (SlashProposal memory proposal);

    /**
     * @notice Returns the total number of slash proposals ever created
     * @return count The total count of proposals (next proposalId will be this value)
     */
    function totalProposals() external view returns (uint256 count);

    /**
     * @notice Checks whether a node is currently banned
     * @param node Address of the node to check
     * @return isBanned True if the node is banned, false otherwise
     */
    function isBanned(address node) external view returns (bool isBanned);

    /**
     * @notice Returns true if the operator has at least one unresolved financial slash proposal.
     * @dev Kept for manager observability. BondingRegistry uses its local lock count.
     * @param operator Operator address to check
     */
    function hasOpenSlashProposal(
        address operator
    ) external view returns (bool);

    /// @notice Freeze all contracts used to validate and execute slashes for an E3.
    /// @dev Called exactly once by the configured Interfold during E3 creation.
    function snapshotE3Dependencies(uint256 e3Id) external;

    /// @notice Release the frozen dependencies for one terminal E3.
    function closeE3(uint256 e3Id) external;

    /// @notice Return the contracts frozen for an E3's slashing lifecycle.
    function getE3Dependencies(
        uint256 e3Id
    )
        external
        view
        returns (
            address bonding,
            address registry,
            address interfoldContract,
            address refundManager
        );

    /// @notice Returns the vote-validity and objective submission deadline frozen for an E3.
    function getE3AccusationWindow(
        uint256 e3Id
    ) external view returns (uint64 voteValidity, uint64 submissionDeadline);

    /// @notice Returns the accusation submission deadline frozen for an E3.
    /// @dev Returns 0 when no snapshot exists. `closeE3` deletes the snapshot
    ///      only after the deadline has passed, so 0 never hides an open window
    ///      for an E3 that once had one. Does not revert, so registries can use
    ///      it to gate collateral release.
    function accusationSubmissionDeadline(
        uint256 e3Id
    ) external view returns (uint64 submissionDeadline);

    /// @notice Returns the resolution eligibility bound for reports admitted by the deadline.
    /// @dev Equals the submission deadline plus the
    ///      maximum appeal window plus the resolution grace. By this time,
    ///      anyone can execute an unappealed proposal or one with a rejected
    ///      appeal, or expire an unresolved appeal. These transactions must
    ///      succeed before settlement. This timestamp never bypasses an open
    ///      proposal. Returns 0 when no snapshot exists.
    function settlementCutoff(
        uint256 e3Id
    ) external view returns (uint64 cutoff);

    /// @notice Whether failed-E3 settlement may proceed now.
    /// @dev Settlement freezes the payer. Both lanes reject new expelling
    ///      proposals after the reporting deadline unless the E3 is Complete.
    ///      Settlement requires the window to close and every expelling
    ///      proposal to reach a terminal outcome, even after settlementCutoff.
    ///      Non-expelling penalties never gate. An E3 without a snapshot, or
    ///      without a finalized committee and any open expelling proposal,
    ///      settles without waiting for the window.
    /// @param e3Id The E3 being settled.
    function settlementOpen(uint256 e3Id) external view returns (bool);

    /// @notice Committee-affecting proposals still open for an E3.
    function openCommitteeProposals(
        uint256 e3Id
    ) external view returns (uint256);

    /// @notice Return a slash route that remains pending after an initial failure.
    function getPendingSlashRoute(
        uint256 proposalId
    ) external view returns (PendingSlashRoute memory);

    /// @notice Permissionlessly retry a pending slash route.
    /// @return routed True when this call completed the route; false when the
    ///         proposal had already been routed or never created a ticket route.
    function retrySlashRoute(uint256 proposalId) external returns (bool routed);

    /// @notice Atomically consume a proposal's reserved funds and account them
    ///         in the snapshotted E3 refund manager.
    /// @dev Self-call only; exposed for try/catch transaction atomicity.
    function routePendingSlashFunds(
        uint256 proposalId
    ) external returns (bool routed);

    /**
     * @notice Returns the bonding registry contract used for executing slashes
     * @return registry The IBondingRegistry contract instance
     */
    function bondingRegistry()
        external
        view
        returns (IBondingRegistry registry);

    /// @notice Returns the bonding-asset identity frozen with a slash policy.
    function slashPolicyAssetContexts(
        bytes32 reason
    ) external view returns (address registry, uint64 configurationVersion);

    /**
     * @notice Returns the ciphernode registry contract used for committee checks and DKG anchors
     * @return registry Address of the ciphernode registry
     */
    function ciphernodeRegistry()
        external
        view
        returns (ICiphernodeRegistry registry);

    // ======================
    // Admin Functions
    // ======================

    /**
     * @notice Creates or updates the slash policy for a specific reason
     * @dev Only callable by GOVERNANCE_ROLE. Validates policy constraints before setting
     * @param reason Hash of the slash reason to configure (must be non-zero)
     * @param policy Complete policy configuration including penalties, proof requirements, and appeal settings
     * Requirements:
     * - reason must not be bytes32(0)
     * - policy.enabled must be true
     * - At least one of ticketPenalty or ciphernodeBondPenalty must be non-zero
     * - If requiresProof is true (Lane A), appealWindow may be 0 (immediate execute) or > 0
     * - If requiresProof is false (Lane B), appealWindow must be greater than 0
     */
    function setSlashPolicy(
        bytes32 reason,
        SlashPolicy calldata policy
    ) external;

    /**
     * @notice Updates the bonding registry contract
     * @dev Only callable by DEFAULT_ADMIN_ROLE. Used to execute actual slashing of funds
     * @param newBondingRegistry The new IBondingRegistry contract (must be non-zero)
     */
    function setBondingRegistry(IBondingRegistry newBondingRegistry) external;

    /**
     * @notice Updates the E3 Refund Manager contract
     * @dev Only callable by DEFAULT_ADMIN_ROLE
     * @param newRefundManager The new IE3RefundManager contract (must be non-zero)
     */
    function setE3RefundManager(IE3RefundManager newRefundManager) external;

    /**
     * @notice Grants SLASHER_ROLE to an address
     * @dev Only callable by DEFAULT_ADMIN_ROLE. Slashers can propose and execute evidence-based slashes
     * @param slasher Address to grant slashing permissions (must be non-zero)
     */
    function addSlasher(address slasher) external;

    /**
     * @notice Revokes SLASHER_ROLE from an address
     * @dev Only callable by DEFAULT_ADMIN_ROLE
     * @param slasher Address to revoke slashing permissions from
     */
    function removeSlasher(address slasher) external;

    // ======================
    // Slashing Functions
    // ======================

    /**
     * @notice Creates a new slash proposal with committee attestation (Lane A - permissionless)
     * @dev Anyone can call this for attestation-based slashes. Requires a quorum of committee
     *      members to have signed votes attesting that the operator submitted a bad proof.
     *      The slash reason is derived deterministically on-chain as
     *      `keccak256(abi.encodePacked(proofType))` — the caller does not pass a reason.
     *      This creates a 1:1 binding between proof types and slash policies, preventing
     *      cross-reason replay attacks.
     *      Evidence format:
     *        abi.encode(uint256 proofType,
     *          address[] voters, bytes32[] dataHashes, bytes evidence,
     *          uint256 issuedAt, uint256 deadline, bytes[] signatures)
     *      Each voter must have signed the EIP-712 digest
     *      `keccak256("\x19\x01" || domainSeparator || structHash)`, where
     *      `structHash = keccak256(abi.encode(VOTE_TYPEHASH, e3Id,
     *      accusationId, voter, dataHash, issuedAt, deadline))`.
     *      where accusationId = keccak256(abi.encodePacked(block.chainid, e3Id, operator, proofType))
     *      Verifications performed:
     *        1. Number of votes >= committee threshold M
     *        2. Voters are sorted ascending (prevents duplicates)
     *        3. Each voter is a committee member for this E3
     *        4. Each vote signature recovers to the declared voter
     *        5. All votes carry the same `dataHash` (no equivocation)
     *        6. `keccak256(evidence) == dataHash`
     *        7. The signed window fits the E3 snapshot and neither the vote nor
     *           the E3's objective slash-submission deadline has expired
     * @param e3Id ID of the E3 computation this slash relates to
     * @param operator Address of the ciphernode operator to slash (must be non-zero)
     * @param proof Attestation evidence:
     *              abi.encode(proofType, voters, dataHashes, evidence,
     *              issuedAt, deadline, signatures)
     * @return proposalId Sequential ID of the created proposal
     */
    function proposeSlash(
        uint256 e3Id,
        address operator,
        bytes calldata proof
    ) external returns (uint256 proposalId);

    /**
     * @notice Creates a new Lane A slash proposal by DKG `partyId` attribution.
     * @dev Resolves `operator = topNodes[partyId]` and requires `partyId` to be present in
     *      `CiphernodeRegistry.getDkgAnchors(e3Id).partyIds` before processing attestation evidence.
     *      This provides an explicit on-chain chain from DKG fold row/slot attribution to operator.
     * @param e3Id ID of the E3 computation this slash relates to
     * @param partyId Canonical committee slot / DKG party identifier
     * @param proof Attestation evidence: abi.encode(proofType, voters, dataHashes,
     *              evidence, issuedAt, deadline, signatures)
     * @return proposalId Sequential ID of the created proposal
     */
    function proposeSlashByDkgParty(
        uint256 e3Id,
        uint256 partyId,
        bytes calldata proof
    ) external returns (uint256 proposalId);

    /**
     * @notice Creates a new slash proposal with evidence (Lane B - SLASHER_ROLE required)
     * @dev Only callable by SLASHER_ROLE. Evidence-based slashes have appeal windows.
     *      After the E3 reporting deadline, an expelling policy requires a Complete E3.
     *      Non-expelling policies do not have this admission deadline.
     * @param e3Id ID of the E3 computation this slash relates to
     * @param operator Address of the ciphernode operator to slash (must be non-zero)
     * @param reason Hash of the slash reason (must have an enabled non-proof policy)
     * @param evidence Evidence data supporting the slash proposal
     * @return proposalId Sequential ID of the created proposal
     */
    function proposeSlashEvidence(
        uint256 e3Id,
        address operator,
        bytes32 reason,
        bytes calldata evidence
    ) external returns (uint256 proposalId);

    /**
     * @notice Executes a slash proposal and applies penalties to the operator
     * @dev For evidence-based slashes, validates appeal window has expired.
     *      Proof-based slashes are executed atomically in proposeSlash.
     * @param proposalId ID of the proposal to execute (must exist and not be already executed)
     */
    function executeSlash(uint256 proposalId) external;

    /**
     * @notice Returns the EIP-712 domain separator used to authenticate attestation votes
     */
    function attestationDomainSeparator() external view returns (bytes32);

    // ======================
    // Appeal Functions
    // ======================

    /**
     * @notice Allows an operator to file an appeal against an evidence-based slash proposal
     * @dev Only the operator being slashed can file an appeal, and only within the appeal window
     * @param proposalId ID of the proposal to appeal (must exist)
     * @param evidence String containing evidence and arguments supporting the appeal
     */
    function fileAppeal(uint256 proposalId, string calldata evidence) external;

    /**
     * @notice Resolves an appeal by accepting or rejecting it
     * @dev Only callable by GOVERNANCE_ROLE. If appeal is upheld, the slash cannot be executed
     * @param proposalId ID of the proposal with the appeal to resolve
     * @param appealUpheld True to uphold the appeal (cancel the slash), false to deny
     * @param resolution String explaining the governance decision
     */
    function resolveAppeal(
        uint256 proposalId,
        bool appealUpheld,
        string calldata resolution
    ) external;

    /**
     * @notice Conclusively upholds an appeal if governance misses its resolution grace period.
     * @dev Permissionless terminal path that releases the operator's collateral gate.
     * @param proposalId ID of the unresolved appealed proposal
     */
    function expireAppeal(uint256 proposalId) external;

    // ======================
    // Ban Management
    // ======================

    /**
     * @notice Proposes a manual ban on a node. Requires a second distinct governance
     *         signer to call `confirmBan`.
     * @dev Only callable by GOVERNANCE_ROLE. Slashing-triggered bans (via `_executeSlash`)
     *      bypass this two-step flow because they are already authorized by the slash
     *      proposal lifecycle. Unbans are single-step via `unbanNode`.
     * @param node Address of the node to ban (must be non-zero)
     * @param reason Hash of the reason for banning
     */
    function proposeBan(address node, bytes32 reason) external;

    /**
     * @notice Confirms a pending ban. Must be called by a governance signer
     *         distinct from the original proposer.
     * @param node Address of the node whose pending ban is being confirmed
     * @param reason Hash of the reason (must match the proposal)
     */
    function confirmBan(address node, bytes32 reason) external;

    /**
     * @notice Cancels a pending ban proposal before it is confirmed.
     * @dev Only callable by GOVERNANCE_ROLE.
     * @param node Address whose pending ban is being cancelled
     */
    function cancelBan(address node) external;

    /**
     * @notice Lifts an existing ban. Single-step because unbanning is a strictly less
     *         dangerous operation than banning.
     * @dev Only callable by GOVERNANCE_ROLE.
     * @param node Address of the node to unban
     * @param reason Hash of the reason for unbanning
     */
    function unbanNode(address node, bytes32 reason) external;

    /**
     * @notice Bans or unbans a node from the network (legacy single-step API).
     * @dev DEPRECATED: For bans, prefer `proposeBan` + `confirmBan` which enforces
     *      a two-signer flow. `updateBanStatus(_, true, _)` reverts with `BanRequiresConfirmation`.
     *      `updateBanStatus(_, false, _)` delegates to `unbanNode`.
     * @param node Address of the node to ban (must be non-zero)
     * @param status Whether to ban the node
     * @param reason Hash of the reason for banning
     */
    function updateBanStatus(
        address node,
        bool status,
        bytes32 reason
    ) external;
}
