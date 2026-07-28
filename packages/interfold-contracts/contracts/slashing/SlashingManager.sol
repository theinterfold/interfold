// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import {
    AccessControlDefaultAdminRules
} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { IE3RefundManager } from "../interfaces/IE3RefundManager.sol";

/**
 * @title SlashingManager
 * @notice Implementation of slashing management with two-lane architecture:
 *         Lane A (proof-based): permissionless, configurable challenge window.
 *         Lane B (evidence-based): SLASHER_ROLE required, appeal window, separate execute.
 * @dev Role-based access control with two-step DEFAULT_ADMIN handover. GOVERNANCE_ROLE
 *      is the admin of SLASHER_ROLE. Attestation votes are authenticated via EIP-712
 * and equivocation across voters is rejected.
 */
contract SlashingManager is
    ISlashingManager,
    AccessControlDefaultAdminRules,
    EIP712
{
    // ======================
    // Constants & Roles
    // ======================

    /// @notice Role identifier for accounts authorized to propose evidence-based slashes
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /// @notice Role identifier for governance accounts that can configure policies, resolve appeals, and manage bans
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /// @notice Upper bound on {SlashPolicy.appealWindow}. Caps the
    ///         period during which governance can delay slash execution.
    uint64 public constant MAX_APPEAL_WINDOW = 30 days;

    /// @notice Maximum time governance has after the appeal window closes to
    ///         resolve a filed appeal. Expiry is fail-safe in the operator's favour.
    uint64 public constant APPEAL_RESOLUTION_GRACE = 7 days;

    /// @notice Emitted when {bondingRegistry} is updated.
    event BondingRegistryUpdated(
        address indexed previous,
        address indexed next
    );

    /// @notice Emitted when {ciphernodeRegistry} is updated.
    event CiphernodeRegistryUpdated(
        address indexed previous,
        address indexed next
    );

    /// @notice Emitted when {interfold} is updated.
    event InterfoldUpdated(address indexed previous, address indexed next);

    /// @notice Emitted when {e3RefundManager} is updated.
    event E3RefundManagerUpdated(
        address indexed previous,
        address indexed next
    );

    // ======================
    // Storage
    // ======================

    /// @notice Reference to the bonding registry contract where slash penalties are executed
    IBondingRegistry public bondingRegistry;

    /// @notice Reference to the ciphernode registry for committee expulsion
    ICiphernodeRegistry public ciphernodeRegistry;

    /// @notice Reference to the Interfold contract for E3 failure signaling
    IInterfold public interfold;

    /// @notice Reference to the E3 Refund Manager for routing slashed funds
    IE3RefundManager public e3RefundManager;

    struct E3Dependencies {
        IBondingRegistry bonding;
        ICiphernodeRegistry registry;
        IInterfold interfoldContract;
        IE3RefundManager refundManager;
        bool initialized;
    }

    /// @notice Contracts frozen for each E3's complete slashing lifecycle.
    mapping(uint256 e3Id => E3Dependencies dependencies)
        internal _e3Dependencies;

    /// @notice Slash routes retained until their reserved ticket funds reach E3 escrow.
    mapping(uint256 proposalId => PendingSlashRoute route)
        internal _pendingSlashRoutes;

    uint256 internal constant INITIAL_ROUTE_GAS = 400_000;
    uint256 internal constant MIN_INITIAL_ROUTE_GAS = 450_000;

    /// @notice Mapping from slash reason hash to its configured policy
    mapping(bytes32 reason => SlashPolicy policy) public slashPolicies;

    /// @notice Internal storage for all slash proposals indexed by proposal ID
    mapping(uint256 proposalId => SlashProposal proposal) internal _proposals;

    /// @notice Counter for total number of slash proposals ever created
    uint256 public totalProposals;

    /// @notice Mapping tracking which nodes are currently banned from the network
    mapping(address node => bool banned) public banned;

    /// @notice Evidence replay protection: tracks consumed evidence keys
    /// @dev Lane A key is keccak256(abi.encodePacked(chainId, e3Id, operator, proofType)) — the accusation identity.
    ///      This prevents the same fault from being slashed multiple times via different voter subsets.
    ///      Lane B key is keccak256(abi.encode(e3Id, operator, keccak256(evidence))) — exact evidence bytes.
    mapping(bytes32 evidenceKey => bool consumed) public evidenceConsumed;

    /// @notice Number of unresolved financial proposals per operator, across both lanes.
    /// @dev Incremented for every proposal and decremented only at successful execution or terminal
    ///      appeal resolution, so collateral cannot leave during a deferred slash.
    mapping(address operator => uint256 openCount) internal _openProposalCount;

    /// @notice Pending two-step manual ban proposals.
    /// @dev `unbanNode` is single-step because it is strictly less dangerous than ban.
    ///      Slashing-triggered bans (via `_executeSlash`) bypass this flow because they are
    ///      already authorized by the slash proposal lifecycle.
    struct PendingBan {
        address proposer;
        bytes32 reason;
        uint256 proposedAt;
    }
    mapping(address node => PendingBan pending) internal _pendingBans;

    // ======================
    // Constants
    // ======================

    /// @notice EIP-712 style typehash for the operator's signed proof payload.
    /// @dev Must match `ProofPayload::typehash()` in `crates/events/src/interfold_event/signed_proof.rs`.
    ///      Prevents cross-chain, cross-E3, and cross-proof-type replay of signed proofs.
    bytes32 public constant PROOF_PAYLOAD_TYPEHASH =
        keccak256(
            "ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)"
        );

    /// @notice EIP-712 typehash for committee attestation votes.
    /// @dev Cross-chain replay is prevented by the EIP-712 domain separator's chainId
    ///      (no need to fold chainId into the struct hash). `agrees` is dropped (always
    ///      true for an accusation), and `deadline` is added so stale signatures are
    ///      rejected by `_verifyAttestationEvidence`. `dataHash` is retained so all
    ///      voters' hashes can be compared for equivocation detection.
    bytes32 public constant VOTE_TYPEHASH =
        keccak256(
            "AccusationVote(uint256 e3Id,bytes32 accusationId,"
            "address voter,bytes32 dataHash,uint256 deadline)"
        );

    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    ///      Exposed for off-chain signers that recompute the domain separator manually
    ///      (e.g. `AccusationManager::vote_domain_separator` in the Rust prover crate).
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    /// @dev EIP-712 domain `name`. Must match the literal passed to `EIP712(...)`
    ///      in the constructor below; off-chain signers MUST hash this exact byte
    ///      string for `recover` to match.
    string public constant EIP712_DOMAIN_NAME = "InterfoldSlashing";

    /// @dev EIP-712 domain `version`. Same alignment rule as `EIP712_DOMAIN_NAME`.
    string public constant EIP712_DOMAIN_VERSION = "1";

    /// @dev `keccak256(bytes(EIP712_DOMAIN_NAME))`.
    bytes32 public constant DOMAIN_NAME_HASH =
        keccak256(bytes(EIP712_DOMAIN_NAME));

    /// @dev `keccak256(bytes(EIP712_DOMAIN_VERSION))`.
    bytes32 public constant DOMAIN_VERSION_HASH =
        keccak256(bytes(EIP712_DOMAIN_VERSION));

    // ======================
    // Modifiers
    // ======================

    /// @notice Restricts function access to accounts with SLASHER_ROLE
    modifier onlySlasher() {
        if (!hasRole(SLASHER_ROLE, msg.sender)) revert Unauthorized();
        _;
    }

    /// @notice Restricts function access to accounts with GOVERNANCE_ROLE
    modifier onlyGovernance() {
        if (!hasRole(GOVERNANCE_ROLE, msg.sender)) revert Unauthorized();
        _;
    }

    // ======================
    // Constructor
    // ======================

    /**
     * @notice Initializes the SlashingManager contract
     * @dev Uses `AccessControlDefaultAdminRules` so `DEFAULT_ADMIN_ROLE` can only be
     *      handed over via the two-step `beginDefaultAdminTransfer` /
     *      `acceptDefaultAdminTransfer` flow with `initialDelay` enforced.
     *      `GOVERNANCE_ROLE` is set as the admin of `SLASHER_ROLE` so slasher membership
     *      is gated by governance rather than the default admin.
     * @param initialDelay Required delay (seconds) between `beginDefaultAdminTransfer`
     *        and `acceptDefaultAdminTransfer`. Production deployments should set a
     *        meaningful value (e.g. 2 days). Pass 0 for local tests.
     * @param admin Address to receive DEFAULT_ADMIN_ROLE and GOVERNANCE_ROLE
     */
    constructor(
        uint48 initialDelay,
        address admin
    )
        AccessControlDefaultAdminRules(initialDelay, admin)
        EIP712(EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION)
    {
        require(admin != address(0), ZeroAddress());
        _grantRole(GOVERNANCE_ROLE, admin);
        // governance — not the default admin — manages slasher membership.
        _setRoleAdmin(SLASHER_ROLE, GOVERNANCE_ROLE);
    }

    // ======================
    // View Functions
    // ======================

    /// @inheritdoc ISlashingManager
    function getSlashPolicy(
        bytes32 reason
    ) external view returns (SlashPolicy memory) {
        return slashPolicies[reason];
    }

    /// @inheritdoc ISlashingManager
    function getSlashProposal(
        uint256 proposalId
    ) external view returns (SlashProposal memory) {
        require(proposalId < totalProposals, InvalidProposal());
        return _proposals[proposalId];
    }

    /// @inheritdoc ISlashingManager
    function isBanned(address node) external view returns (bool) {
        return banned[node];
    }

    /// @inheritdoc ISlashingManager
    function hasOpenSlashProposal(
        address operator
    ) external view returns (bool) {
        return _openProposalCount[operator] > 0;
    }

    /// @inheritdoc ISlashingManager
    function attestationDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc ISlashingManager
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
        )
    {
        E3Dependencies memory dependencies = _dependenciesFor(e3Id);
        return (
            address(dependencies.bonding),
            address(dependencies.registry),
            address(dependencies.interfoldContract),
            address(dependencies.refundManager)
        );
    }

    /// @inheritdoc ISlashingManager
    function getPendingSlashRoute(
        uint256 proposalId
    ) external view returns (PendingSlashRoute memory) {
        return _pendingSlashRoutes[proposalId];
    }

    /// @inheritdoc ISlashingManager
    function retrySlashRoute(
        uint256 proposalId
    ) external returns (bool routed) {
        if (!_pendingSlashRoutes[proposalId].pending) return false;
        return this.routePendingSlashFunds(proposalId);
    }

    /// @inheritdoc ISlashingManager
    function snapshotE3Dependencies(uint256 e3Id) external {
        require(
            msg.sender == address(interfold) ||
                msg.sender == address(ciphernodeRegistry),
            Unauthorized()
        );
        E3Dependencies storage dependencies = _e3Dependencies[e3Id];
        require(!dependencies.initialized, InvalidProposal());
        dependencies.bonding = bondingRegistry;
        dependencies.registry = ciphernodeRegistry;
        dependencies.interfoldContract = interfold;
        dependencies.refundManager = e3RefundManager;
        dependencies.initialized = true;
    }

    // ======================
    // Admin Functions
    // ======================

    /// @inheritdoc ISlashingManager
    function setSlashPolicy(
        bytes32 reason,
        SlashPolicy calldata policy
    ) external onlyRole(GOVERNANCE_ROLE) {
        require(reason != bytes32(0), InvalidPolicy());
        // `enabled = false` is allowed so governance can pre-stage / pause a policy.
        // Per-call enforcement happens in `proposeSlash` / `proposeSlashEvidence`.
        require(
            policy.ticketPenalty > 0 || policy.licensePenalty > 0,
            InvalidPolicy()
        );

        // Evidence-based (Lane B) policies require a non-zero `appealWindow`.
        // Proof-based (Lane A) may use `appealWindow == 0` for atomic propose+execute.
        if (!policy.requiresProof) {
            require(policy.appealWindow > 0, InvalidPolicy());
        }
        // Cap the appeal window so governance cannot indefinitely delay slashing.
        require(policy.appealWindow <= MAX_APPEAL_WINDOW, InvalidPolicy());
        if (policy.failureReason > 0) {
            // A policy that can fail an E3 must also remove the proven-faulty
            // operator before the refund manager snapshots honest recipients.
            require(policy.affectsCommittee, InvalidPolicy());
            require(
                policy.failureReason <
                    uint8(IInterfold.FailureReason._MAX_FAILURE_REASON),
                InvalidPolicy()
            );
        }

        slashPolicies[reason] = policy;
        emit SlashPolicyUpdated(reason, policy);
    }

    /// @inheritdoc ISlashingManager
    function setBondingRegistry(
        IBondingRegistry newBondingRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(address(newBondingRegistry) != address(0), ZeroAddress());
        address oldValue = address(bondingRegistry);
        bondingRegistry = newBondingRegistry;
        emit BondingRegistryUpdated(oldValue, address(newBondingRegistry));
    }

    /// @notice Updates the ciphernode registry contract
    /// @param newCiphernodeRegistry The new ICiphernodeRegistry contract
    function setCiphernodeRegistry(
        ICiphernodeRegistry newCiphernodeRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(address(newCiphernodeRegistry) != address(0), ZeroAddress());
        address oldValue = address(ciphernodeRegistry);
        ciphernodeRegistry = newCiphernodeRegistry;
        emit CiphernodeRegistryUpdated(
            oldValue,
            address(newCiphernodeRegistry)
        );
    }

    /// @notice Updates the Interfold contract
    /// @param newInterfold The new IInterfold contract
    function setInterfold(
        IInterfold newInterfold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(address(newInterfold) != address(0), ZeroAddress());
        address oldValue = address(interfold);
        interfold = newInterfold;
        emit InterfoldUpdated(oldValue, address(newInterfold));
    }

    /// @inheritdoc ISlashingManager
    function setE3RefundManager(
        IE3RefundManager newRefundManager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(address(newRefundManager) != address(0), ZeroAddress());
        address oldValue = address(e3RefundManager);
        e3RefundManager = newRefundManager;
        emit E3RefundManagerUpdated(oldValue, address(newRefundManager));
    }

    /// @inheritdoc ISlashingManager
    /// @dev Slasher membership is administered via `GOVERNANCE_ROLE`, not the default
    ///      admin, so a compromised default admin alone cannot grant SLASHER_ROLE.
    function addSlasher(address slasher) external onlyRole(GOVERNANCE_ROLE) {
        require(slasher != address(0), ZeroAddress());
        _grantRole(SLASHER_ROLE, slasher);
    }

    /// @inheritdoc ISlashingManager
    function removeSlasher(address slasher) external onlyRole(GOVERNANCE_ROLE) {
        _revokeRole(SLASHER_ROLE, slasher);
    }

    // ======================
    // Slashing Functions
    // ======================

    /// @inheritdoc ISlashingManager
    /// @dev Lane A permissionless attestation-based slash. Reason is derived as
    ///      `keccak256(abi.encodePacked(proofType))` (prevents cross-reason replay).
    ///      Execution is atomic when `policy.appealWindow == 0`, otherwise deferred so
    ///      the accused can {fileAppeal}. Evidence format:
    ///      `abi.encode(uint256 proofType, address[] voters, bytes32[] dataHashes,
    ///      bytes evidence, uint256 deadline, bytes[] signatures)`. Voters sign the EIP-712
    ///      `AccusationVote` against this contract's domain; all `dataHash` values
    ///      must be identical and equal `keccak256(evidence)`.
    function proposeSlash(
        uint256 e3Id,
        address operator,
        bytes calldata proof
    ) external returns (uint256 proposalId) {
        return _proposeSlash(e3Id, operator, proof);
    }

    /// @inheritdoc ISlashingManager
    /// @dev Additive attribution path: resolves `operator` from DKG anchors and
    ///      canonical committee slot before reusing Lane A attestation validation.
    function proposeSlashByDkgParty(
        uint256 e3Id,
        uint256 partyId,
        bytes calldata proof
    ) external returns (uint256 proposalId) {
        address operator = _resolveDkgPartyOperator(e3Id, partyId);
        return _proposeSlash(e3Id, operator, proof);
    }

    function _proposeSlash(
        uint256 e3Id,
        address operator,
        bytes calldata proof
    ) internal returns (uint256 proposalId) {
        require(operator != address(0), ZeroAddress());
        require(proof.length != 0, ProofRequired());

        // Extract proofType and derive the slash reason deterministically.
        uint256 proofType = abi.decode(proof, (uint256));
        bytes32 reason = keccak256(abi.encodePacked(proofType));

        SlashPolicy memory policy = slashPolicies[reason];
        require(policy.enabled, SlashReasonDisabled());
        require(policy.requiresProof, InvalidPolicy());

        require(
            _dependenciesFor(e3Id).registry.isCommitteeMember(e3Id, operator),
            OperatorNotInCommittee()
        );

        // Evidence replay protection — reason-independent to prevent cross-reason replay
        bytes32 evidenceKey = keccak256(
            abi.encodePacked(block.chainid, e3Id, operator, proofType)
        );
        require(!evidenceConsumed[evidenceKey], DuplicateEvidence());
        evidenceConsumed[evidenceKey] = true;

        // Verify committee attestation: vote signatures, quorum, equivocation, deadline
        _verifyAttestationEvidence(proof, e3Id, operator);

        // Create proposal
        proposalId = totalProposals;
        totalProposals = proposalId + 1;

        uint256 executableAt = block.timestamp + policy.appealWindow;
        SlashProposal storage p = _proposals[proposalId];
        p.e3Id = e3Id;
        p.operator = operator;
        p.reason = reason;
        p.ticketAmount = policy.ticketPenalty;
        p.licenseAmount = policy.licensePenalty;
        p.proposedAt = block.timestamp;
        p.executableAt = executableAt;
        p.proposer = msg.sender;
        p.proofHash = keccak256(proof);
        p.proofVerified = true;
        p.banNode = policy.banNode;
        p.affectsCommittee = policy.affectsCommittee;
        p.failureReason = policy.failureReason;

        _openProposalCount[operator] += 1;

        emit SlashProposed(
            proposalId,
            e3Id,
            operator,
            reason,
            policy.ticketPenalty,
            policy.licensePenalty,
            executableAt,
            msg.sender,
            Lane.LaneA
        );

        // Legacy atomic path: when no challenge window is configured, execute now.
        // Otherwise defer to `executeSlash` after `executableAt`.
        if (policy.appealWindow == 0) {
            _openProposalCount[operator] -= 1;
            _executeSlash(proposalId, Lane.LaneA);
        }
    }

    /// @dev Resolve a slash target from DKG anchors:
    ///      - `partyId` must be present in `getDkgAnchors(e3Id).partyIds`
    ///      - operator is resolved as canonical committee slot `topNodes[partyId]`
    function _resolveDkgPartyOperator(
        uint256 e3Id,
        uint256 partyId
    ) internal view returns (address operator) {
        ICiphernodeRegistry registry = _dependenciesFor(e3Id).registry;
        (uint256[] memory partyIds, , ) = registry.getDkgAnchors(e3Id);
        bool found = false;
        for (uint256 i = 0; i < partyIds.length; i++) {
            if (partyIds[i] == partyId) {
                found = true;
                break;
            }
        }
        require(found, PartyIdNotInDkgAnchors());
        return registry.canonicalCommitteeNodeAt(e3Id, partyId);
    }

    /// @inheritdoc ISlashingManager
    /// @dev Lane B: Evidence-based slash with appeal window. SLASHER_ROLE required.
    function proposeSlashEvidence(
        uint256 e3Id,
        address operator,
        bytes32 reason,
        bytes calldata evidence
    ) external onlySlasher returns (uint256 proposalId) {
        require(operator != address(0), ZeroAddress());

        SlashPolicy memory policy = slashPolicies[reason];
        require(policy.enabled, SlashReasonDisabled());
        require(!policy.requiresProof, InvalidPolicy());
        require(
            _dependenciesFor(e3Id).registry.isCommitteeMember(e3Id, operator),
            OperatorNotInCommittee()
        );

        // Evidence replay protection — reason-independent to prevent cross-reason replay
        bytes32 evidenceKey = keccak256(
            abi.encode(e3Id, operator, keccak256(evidence))
        );
        require(!evidenceConsumed[evidenceKey], DuplicateEvidence());
        evidenceConsumed[evidenceKey] = true;

        proposalId = totalProposals;
        totalProposals = proposalId + 1;

        // Track the unresolved proposal so collateral remains slashable until
        // successful execution or terminal appeal resolution.
        _openProposalCount[operator] += 1;

        uint256 executableAt = block.timestamp + policy.appealWindow;
        SlashProposal storage p = _proposals[proposalId];
        p.e3Id = e3Id;
        p.operator = operator;
        p.reason = reason;
        p.ticketAmount = policy.ticketPenalty;
        p.licenseAmount = policy.licensePenalty;
        p.proposedAt = block.timestamp;
        p.executableAt = executableAt;
        p.proposer = msg.sender;
        p.proofHash = keccak256(evidence);
        // Snapshot behavioral flags from policy at proposal time
        // to prevent execution drift if policy is modified during appeal window
        p.banNode = policy.banNode;
        p.affectsCommittee = policy.affectsCommittee;
        p.failureReason = policy.failureReason;

        emit SlashProposed(
            proposalId,
            e3Id,
            operator,
            reason,
            policy.ticketPenalty,
            policy.licensePenalty,
            executableAt,
            msg.sender,
            Lane.LaneB
        );
    }

    /// @inheritdoc ISlashingManager
    /// @dev Executes a deferred Lane A or Lane B proposal after the appeal window has elapsed.
    function executeSlash(uint256 proposalId) external {
        require(proposalId < totalProposals, InvalidProposal());
        SlashProposal storage p = _proposals[proposalId];
        require(!p.executed, AlreadyExecuted());

        // Appeal-window check applies to both lanes whenever it is in the future.
        require(block.timestamp >= p.executableAt, AppealWindowActive());
        if (p.appealed) {
            require(p.resolved, AppealPending());
            require(!p.appealUpheld, AppealUpheld());
        }

        Lane lane = p.proofVerified ? Lane.LaneA : Lane.LaneB;
        // Decrement BEFORE `_executeSlash` so a reentrant operator action triggered
        // by slash side-effects is not gated on this proposal. Other open proposals
        // keep the gate raised. A downstream revert restores the count atomically.
        _openProposalCount[p.operator] -= 1;

        _executeSlash(proposalId, lane);
    }

    // ======================
    // Internal Execution
    // ======================

    /// @dev Verifies Lane A attestation evidence: decodes, checks quorum (>= M), verifies
    ///      each EIP-712 `AccusationVote` signature, confirms voters are active committee
    ///      members, enforces the shared `deadline`, and rejects equivocation (all
    ///      `dataHash` values must match and bind to `keccak256(evidence)`).
    ///      Voters must be sorted ascending (no duplicates).
    function _verifyAttestationEvidence(
        bytes calldata proof,
        uint256 e3Id,
        address operator
    ) internal view {
        (
            uint256 proofType,
            address[] memory voters,
            bytes32[] memory dataHashes,
            bytes memory evidence,
            uint256 deadline,
            bytes[] memory signatures
        ) = abi.decode(
                proof,
                (uint256, address[], bytes32[], bytes, uint256, bytes[])
            );

        uint256 numVotes = voters.length;
        require(
            numVotes == dataHashes.length && numVotes == signatures.length,
            InvalidProof()
        );
        require(block.timestamp <= deadline, SignatureExpired());

        // Compute accusation ID matching AccusationManager::accusation_id() on the Rust side
        bytes32 accusationId = keccak256(
            abi.encodePacked(block.chainid, e3Id, operator, proofType)
        );

        // Get committee threshold — need at least M agreeing votes
        {
            uint32 thresholdM = _committeeThresholdM(e3Id);
            require(thresholdM > 0, InvalidProposal());
            require(numVotes >= thresholdM, InsufficientAttestations());
        }

        // detect equivocation across voters — the entire committee must agree
        // on the exact `dataHash` they witnessed. Divergent hashes indicate at least
        // one voter is signing inconsistent statements and the attestation must not be
        // accepted as a single fault witness.
        bytes32 sharedDataHash = dataHashes[0];
        require(keccak256(evidence) == sharedDataHash, InvalidProof());

        // Verify each vote signature and membership
        address prevVoter = address(0);
        for (uint256 i = 0; i < numVotes; i++) {
            address voter = voters[i];

            // Sorted ascending order prevents duplicate voters
            require(voter > prevVoter, DuplicateVoter());
            prevVoter = voter;

            // The accused cannot vote on their own accusation (conflict of interest)
            require(voter != operator, VoterIsAccused());

            // every voter must witness the same data hash
            require(dataHashes[i] == sharedDataHash, EquivocationDetected());

            // Verify voter is an active committee member for this E3
            require(
                _isCommitteeMemberActive(e3Id, voter),
                VoterNotInCommittee()
            );

            // EIP-712 vote digest — cross-chain replay is prevented by the domain
            // separator's chainId, and cross-contract replay by `verifyingContract`.
            // Scoped block avoids stack-too-deep.
            {
                bytes32 structHash = keccak256(
                    abi.encode(
                        VOTE_TYPEHASH,
                        e3Id,
                        accusationId,
                        voter,
                        dataHashes[i],
                        deadline
                    )
                );
                bytes32 digest = _hashTypedDataV4(structHash);
                require(
                    ECDSA.recover(digest, signatures[i]) == voter,
                    InvalidVoteSignature()
                );
            }
        }
    }

    function _committeeThresholdM(
        uint256 e3Id
    ) internal view returns (uint32 thresholdM) {
        (, thresholdM, , ) = _dependenciesFor(e3Id)
            .registry
            .getCommitteeViability(e3Id);
    }

    function _isCommitteeMemberActive(
        uint256 e3Id,
        address voter
    ) internal view returns (bool) {
        return
            _dependenciesFor(e3Id).registry.isCommitteeMemberActive(
                e3Id,
                voter
            );
    }

    /// @dev Executes a slash: applies financial penalties, optional ban, and committee expulsion.
    ///      BondingRegistry keeps active and queued collateral locked while any
    ///      proposal from a retained slashing manager remains unresolved.
    /// @dev `p.executed = true` is deferred until AFTER the two `bondingRegistry.slash*`
    ///      calls succeed but BEFORE any other external interaction. This protects the
    ///      proposal from being permanently marked as executed when the financial leg
    ///      reverts (e.g. an attacker griefs the operator's exit queue with enough
    ///      tranches to OOG `_takeAssetsFromQueue`). The `MAX_ACTIVE_TRANCHES` cap is
    ///      the primary defence; this ordering provides defence-in-depth.
    function _executeSlash(uint256 proposalId, Lane lane) internal {
        SlashProposal storage p = _proposals[proposalId];
        E3Dependencies memory dependencies = _dependenciesFor(p.e3Id);

        uint256 actualTicketSlashed = 0;

        // Execute financial penalties
        if (p.ticketAmount > 0) {
            actualTicketSlashed = dependencies.bonding.slashTicketBalance(
                p.operator,
                p.ticketAmount,
                p.reason
            );
        }

        if (p.licenseAmount > 0) {
            dependencies.bonding.slashLicenseBond(
                p.operator,
                p.licenseAmount,
                p.reason
            );
        }

        // Financial penalties succeeded — commit `executed` before any further
        // external interaction (committee expulsion, refund escrow self-call,
        // interfold routing) so that reentrancy via those paths cannot re-enter
        // _executeSlash for the same proposal, while still allowing a deferred
        // proposal to retry if either bondingRegistry.slash* leg above reverts.
        p.executed = true;

        // Ban node if snapshotted policy requires it
        if (p.banNode) {
            banned[p.operator] = true;
            emit NodeBanUpdated(p.operator, true, p.reason, address(this));
            _refreshOperatorEligibility(dependencies.bonding, p.operator);
        }

        // Committee expulsion for E3-scoped slashes (uses snapshotted behavioral flags)
        // expelCommitteeMember returns (activeCount, thresholdM) — one call instead of three
        if (p.affectsCommittee) {
            (uint256 activeCount, uint32 thresholdM) = dependencies
                .registry
                .expelCommitteeMember(p.e3Id, p.operator, p.reason);

            // If active count drops below M, fail the E3
            if (activeCount < thresholdM && p.failureReason > 0) {
                // NOTE: catch block must not be empty (solc optimizer bug, see below)
                // solhint-disable-next-line no-empty-blocks
                try
                    dependencies.interfoldContract.onE3Failed(
                        p.e3Id,
                        p.failureReason
                    )
                {
                    // Side effects occur in the external call
                } catch {
                    // E3 already failed or other error — slash still proceeds
                    emit RoutingFailed(p.e3Id, 0);
                }
            }
        }

        // Reserve and attempt escrow. Failure leaves both a durable proposal
        // route and a matching BondingRegistry reservation for permissionless retry.
        if (actualTicketSlashed > 0) {
            dependencies.bonding.reserveSlashedTicketFunds(actualTicketSlashed);
            PendingSlashRoute storage route = _pendingSlashRoutes[proposalId];
            route.e3Id = p.e3Id;
            route.token = address(
                dependencies.bonding.ticketToken().underlying()
            );
            route.amount = actualTicketSlashed;
            route.pending = true;
            emit SlashRoutePending(
                proposalId,
                p.e3Id,
                route.token,
                actualTicketSlashed
            );

            require(
                gasleft() >= MIN_INITIAL_ROUTE_GAS,
                InsufficientRoutingGas()
            );
            try
                this.routePendingSlashFunds{ gas: INITIAL_ROUTE_GAS }(
                    proposalId
                )
            returns (bool routed) {
                require(routed, InvalidProposal());
            } catch {
                emit RoutingFailed(p.e3Id, actualTicketSlashed);
            }
        }

        emit SlashExecuted(
            proposalId,
            p.e3Id,
            p.operator,
            p.reason,
            p.ticketAmount,
            p.licenseAmount,
            true,
            lane
        );
    }

    /// @inheritdoc ISlashingManager
    function routePendingSlashFunds(
        uint256 proposalId
    ) external returns (bool routed) {
        require(msg.sender == address(this), Unauthorized());
        PendingSlashRoute storage route = _pendingSlashRoutes[proposalId];
        require(route.pending, InvalidProposal());

        E3Dependencies memory dependencies = _dependenciesFor(route.e3Id);
        // Clear before interacting so a callback cannot route the same reserve
        // twice. Any downstream failure reverts this write together with the
        // transfer and accounting, leaving the route pending for another retry.
        route.pending = false;
        dependencies.bonding.redirectReservedSlashedTicketFunds(
            address(dependencies.refundManager),
            route.amount
        );
        dependencies.interfoldContract.escrowSlashedFunds(
            route.e3Id,
            IERC20(route.token),
            route.amount
        );
        emit SlashedFundsEscrowedToRefund(
            route.e3Id,
            route.token,
            route.amount
        );
        emit SlashRouteCompleted(
            proposalId,
            route.e3Id,
            route.token,
            route.amount
        );
        return true;
    }

    function _dependenciesFor(
        uint256 e3Id
    ) internal view returns (E3Dependencies memory dependencies) {
        dependencies = _e3Dependencies[e3Id];
        require(dependencies.initialized, InvalidProposal());
    }

    // ======================
    // Appeal Functions
    // ======================

    /// @inheritdoc ISlashingManager
    /// @dev Only the accused operator may appeal (no delegate support). Consider an `appealDelegate`
    ///      mapping for production to handle lost-key or banned-operator scenarios.
    ///      Appeals are now permitted for proof-verified (Lane A) proposals when their
    ///      policy is configured with a non-zero `appealWindow`.
    function fileAppeal(uint256 proposalId, string calldata evidence) external {
        require(proposalId < totalProposals, InvalidProposal());
        SlashProposal storage p = _proposals[proposalId];

        // Only the accused can appeal
        require(msg.sender == p.operator, Unauthorized());
        // Already-executed slashes (Lane A with appealWindow == 0) cannot be appealed.
        require(!p.executed, AlreadyExecuted());
        // Only within the appeal window
        require(block.timestamp < p.executableAt, AppealWindowExpired());
        // Only once
        require(!p.appealed, AlreadyAppealed());

        p.appealed = true;

        emit AppealFiled(proposalId, p.operator, p.reason, evidence);
    }

    /// @inheritdoc ISlashingManager
    function resolveAppeal(
        uint256 proposalId,
        bool appealUpheld,
        string calldata resolution
    ) external onlyGovernance {
        require(proposalId < totalProposals, InvalidProposal());
        SlashProposal storage p = _proposals[proposalId];

        require(p.appealed, InvalidProposal());
        require(!p.resolved, AlreadyResolved());

        p.resolved = true;
        p.appealUpheld = appealUpheld;

        // An upheld appeal terminates the proposal, so its collateral gate ends.
        if (appealUpheld) {
            _openProposalCount[p.operator] -= 1;
        }

        emit AppealResolved(
            proposalId,
            p.operator,
            appealUpheld,
            msg.sender,
            resolution
        );
    }

    /// @inheritdoc ISlashingManager
    function expireAppeal(uint256 proposalId) external {
        require(proposalId < totalProposals, InvalidProposal());
        SlashProposal storage p = _proposals[proposalId];
        require(p.appealed, InvalidProposal());
        require(!p.resolved, AlreadyResolved());
        require(!p.executed, AlreadyExecuted());
        require(
            block.timestamp >= p.executableAt + APPEAL_RESOLUTION_GRACE,
            AppealResolutionWindowActive()
        );

        p.resolved = true;
        p.appealUpheld = true;
        _openProposalCount[p.operator] -= 1;

        emit AppealResolved(
            proposalId,
            p.operator,
            true,
            msg.sender,
            "governance resolution window expired"
        );
    }

    // ======================
    // Ban Management
    // ======================

    /// @inheritdoc ISlashingManager
    function proposeBan(address node, bytes32 reason) external onlyGovernance {
        require(node != address(0), ZeroAddress());
        require(!banned[node], InvalidPolicy());

        _pendingBans[node] = PendingBan({
            proposer: msg.sender,
            reason: reason,
            proposedAt: block.timestamp
        });

        emit BanProposed(node, reason, msg.sender);
    }

    /// @inheritdoc ISlashingManager
    function confirmBan(address node, bytes32 reason) external onlyGovernance {
        PendingBan memory pending = _pendingBans[node];
        require(pending.proposer != address(0), NoPendingBan());
        require(pending.reason == reason, InvalidPolicy());
        // a single governance signer cannot both propose and confirm a manual ban.
        require(pending.proposer != msg.sender, BanRequiresConfirmation());

        delete _pendingBans[node];
        banned[node] = true;

        emit NodeBanUpdated(node, true, reason, msg.sender);
        _refreshOperatorEligibility(bondingRegistry, node);
    }

    /// @inheritdoc ISlashingManager
    function cancelBan(address node) external onlyGovernance {
        require(_pendingBans[node].proposer != address(0), NoPendingBan());
        delete _pendingBans[node];
        emit BanCancelled(node, msg.sender);
    }

    /// @inheritdoc ISlashingManager
    function unbanNode(address node, bytes32 reason) external onlyGovernance {
        require(node != address(0), ZeroAddress());
        banned[node] = false;
        if (_pendingBans[node].proposer != address(0)) {
            delete _pendingBans[node];
            emit BanCancelled(node, msg.sender);
        }
        emit NodeBanUpdated(node, false, reason, msg.sender);
        _refreshOperatorEligibility(bondingRegistry, node);
    }

    /// @inheritdoc ISlashingManager
    function updateBanStatus(
        address node,
        bool status,
        bytes32 reason
    ) external onlyGovernance {
        require(node != address(0), ZeroAddress());
        // bans must use the two-step `proposeBan` / `confirmBan` flow.
        require(!status, BanRequiresConfirmation());
        banned[node] = false;
        if (_pendingBans[node].proposer != address(0)) {
            delete _pendingBans[node];
            emit BanCancelled(node, msg.sender);
        }
        emit NodeBanUpdated(node, false, reason, msg.sender);
        _refreshOperatorEligibility(bondingRegistry, node);
    }

    /// @dev Synchronizes the BondingRegistry active count after a ban changes.
    ///      An unset test or deployment dependency cannot block ban state.
    function _refreshOperatorEligibility(
        IBondingRegistry registry,
        address operator
    ) private {
        if (address(registry).code.length == 0) return;
        if (registry.isRegistered(operator)) {
            registry.refreshOperatorStatus(operator);
        }
    }

    /// @notice ERC-165 interface detection. Advertises {ISlashingManager}
    ///         in addition to interfaces inherited from
    ///         {AccessControlDefaultAdminRules}.
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            interfaceId == type(ISlashingManager).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
