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
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { IE3RefundManager } from "../interfaces/IE3RefundManager.sol";
import { SlashingEvidenceLib } from "../lib/SlashingEvidenceLib.sol";

/**
 * @title SlashingManager
 * @notice Implementation of slashing management with two-lane architecture:
 *         Lane A (proof-based): permissionless, configurable challenge window.
 *         Lane B (evidence-based): SLASHER_ROLE required, appeal window, separate execute.
 * @dev Role-based access control with two-step DEFAULT_ADMIN handover. GOVERNANCE_ROLE
 *      is the admin of SLASHER_ROLE. Attestation votes are authenticated via EIP-712
 * and equivocation across voters is rejected.
 */
// solhint-disable-next-line max-states-count
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

    /// @inheritdoc ISlashingManager
    uint256 public constant SLASHING_MANAGER_API_VERSION = 1;

    /// @notice Role identifier for governance accounts that can configure policies, resolve appeals, and manage bans
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /// @notice Upper bound on {SlashPolicy.appealWindow}. Caps the
    ///         period during which governance can delay slash execution.
    uint64 public constant MAX_APPEAL_WINDOW = 30 days;

    /// @notice Maximum time governance has after the appeal window closes to
    ///         resolve a filed appeal. Expiry is fail-safe in the operator's favour.
    uint64 public constant APPEAL_RESOLUTION_GRACE = 7 days;

    /// @notice Time after the latest possible E3 lifecycle deadline for Lane A reports.
    uint64 public constant ACCUSATION_REPORTING_WINDOW = 1 days;

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
        uint64 accusationVoteValidity;
        uint64 slashSubmissionDeadline;
        bool initialized;
    }

    /// @notice Contracts frozen for each E3's complete slashing lifecycle.
    mapping(uint256 e3Id => E3Dependencies dependencies)
        internal _e3Dependencies;

    /// @notice Slash routes retained until their reserved ticket funds reach E3 escrow.
    mapping(uint256 proposalId => PendingSlashRoute route)
        internal _pendingSlashRoutes;

    /// @dev Gas handed to the first routing attempt. The route walks the committee
    ///      once per eligibility pass and, since the ZEN2-20 follow-up, also skips
    ///      every operator this E3 has penalized. That check costs about 28k gas
    ///      on a three-member committee and grows with committee size, so the
    ///      stipend was widened from 400k rather than trimming the check. A route
    ///      that still runs out stays pending for `retrySlashRoute`.
    uint256 internal constant INITIAL_ROUTE_GAS = 500_000;
    /// @dev Gas the caller must still hold before the routing attempt. Keeps the
    ///      same margin over `INITIAL_ROUTE_GAS` as before, plus the 63/64 share
    ///      the EVM withholds from a nested call.
    uint256 internal constant MIN_INITIAL_ROUTE_GAS = 560_000;

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
    /// @notice Open committee-affecting proposals per E3.
    /// @dev ZEN2-04 follow-up. `settlementOpen` reads it so failed-E3 settlement
    ///      cannot freeze the payer while an expulsion is still pending. Kept
    ///      beside the per-operator count and moved with it at every site.
    mapping(uint256 e3Id => uint256 openCount) internal _openCommitteeProposals;

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

    /// @notice Bonding-asset identity frozen when each policy is configured.
    mapping(bytes32 reason => SlashPolicyAssetContext context)
        public slashPolicyAssetContexts;

    /// @inheritdoc ISlashingManager
    uint256 public activeE3Assignments;

    /// @inheritdoc ISlashingManager
    uint256 public activeBanCount;

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
    ///      true for an accusation). `issuedAt` and `deadline` bind the vote to the
    ///      E3's snapshotted validity window. `dataHash` is retained so all voters'
    ///      hashes can be compared for equivocation detection.
    bytes32 public constant VOTE_TYPEHASH =
        keccak256(
            "AccusationVote(uint256 e3Id,bytes32 accusationId,"
            "address voter,bytes32 dataHash,uint256 issuedAt,uint256 deadline)"
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
    function getE3AccusationWindow(
        uint256 e3Id
    ) external view returns (uint64 voteValidity, uint64 submissionDeadline) {
        E3Dependencies memory dependencies = _dependenciesFor(e3Id);
        return (
            dependencies.accusationVoteValidity,
            dependencies.slashSubmissionDeadline
        );
    }

    /// @inheritdoc ISlashingManager
    function accusationSubmissionDeadline(
        uint256 e3Id
    ) external view returns (uint64 submissionDeadline) {
        return _e3Dependencies[e3Id].slashSubmissionDeadline;
    }

    /// @inheritdoc ISlashingManager
    function settlementCutoff(
        uint256 e3Id
    ) external view returns (uint64 cutoff) {
        return _settlementCutoff(_e3Dependencies[e3Id].slashSubmissionDeadline);
    }

    /// @inheritdoc ISlashingManager
    function settlementOpen(uint256 e3Id) external view returns (bool) {
        E3Dependencies storage dependencies = _e3Dependencies[e3Id];
        uint64 deadline = dependencies.slashSubmissionDeadline;
        if (deadline == 0) return true;
        if (block.timestamp > _settlementCutoff(deadline)) return true;
        if (_openCommitteeProposals[e3Id] != 0) return false;
        // No committee was ever finalized: there is no member to expel and no
        // payer to move, so the accusation window is not waited for.
        // `canonicalCommitteeNodeAt(e3Id, 0)` reverts `CommitteeNotFinalized`
        // before finalization and answers afterwards, including for a round
        // that has since lost every member, so it is the one read that tells
        // the two apart.
        if (!_committeeFinalized(dependencies.registry, e3Id)) return true;
        return block.timestamp > deadline;
    }

    /// @inheritdoc ISlashingManager
    function openCommitteeProposals(
        uint256 e3Id
    ) external view returns (uint256) {
        return _openCommitteeProposals[e3Id];
    }

    /// @dev True once the registry finalized a committee for `e3Id`. Reads the
    ///      canonical slot 0, which the registry refuses to expose before
    ///      finalization; the revert is the signal, so it is caught, not
    ///      propagated. Empty revert data (an EOA or a registry without the
    ///      view) is read as not finalized, which only delays settlement.
    function _committeeFinalized(
        ICiphernodeRegistry registry,
        uint256 e3Id
    ) internal view returns (bool) {
        try registry.canonicalCommitteeNodeAt(e3Id, 0) returns (address) {
            return true;
        } catch {
            return false;
        }
    }

    function _settlementCutoff(uint64 deadline) internal pure returns (uint64) {
        if (deadline == 0) return 0;
        return deadline + MAX_APPEAL_WINDOW + APPEAL_RESOLUTION_GRACE;
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
        uint256 voteValidity = dependencies.registry.accusationVoteValidity();
        uint256 lifecycleDeadline = dependencies
            .interfoldContract
            .getE3LifecycleDeadline(e3Id);
        require(
            voteValidity <= type(uint64).max &&
                lifecycleDeadline <=
                type(uint64).max - ACCUSATION_REPORTING_WINDOW,
            InvalidProposal()
        );
        dependencies.accusationVoteValidity = uint64(voteValidity);
        dependencies.slashSubmissionDeadline =
            uint64(lifecycleDeadline) +
            ACCUSATION_REPORTING_WINDOW;
        dependencies.initialized = true;
        activeE3Assignments++;
        dependencies.bonding.snapshotSlashRouteDestination(
            e3Id,
            address(dependencies.refundManager),
            address(dependencies.interfoldContract)
        );
    }

    /// @inheritdoc ISlashingManager
    function closeE3(uint256 e3Id) external onlyGovernance {
        E3Dependencies memory dependencies = _dependenciesFor(e3Id);
        if (block.timestamp <= dependencies.slashSubmissionDeadline) {
            revert AccusationWindowOpen(
                e3Id,
                dependencies.slashSubmissionDeadline
            );
        }
        dependencies.bonding.releaseSlashRouteDestination(e3Id);
        delete _e3Dependencies[e3Id];
        activeE3Assignments--;
        emit E3DependenciesReleased(e3Id);
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
            policy.ticketPenalty > 0 || policy.ciphernodeBondPenalty > 0,
            InvalidPolicy()
        );

        // Evidence-based (Lane B) policies require a non-zero `appealWindow`.
        // Proof-based (Lane A) may use `appealWindow == 0` for atomic propose+execute.
        if (!policy.requiresProof) {
            require(policy.appealWindow > 0, InvalidPolicy());
        }
        // Cap the appeal window so governance cannot indefinitely delay slashing.
        require(policy.appealWindow <= MAX_APPEAL_WINDOW, InvalidPolicy());
        // Threshold loss uses the existing supplier-paid insufficient-members
        // reason. The field remains in the policy struct for ABI and storage compatibility.
        require(
            policy.failureReason == 0 ||
                (policy.affectsCommittee &&
                    policy.failureReason ==
                    uint8(
                        IInterfold.FailureReason.InsufficientCommitteeMembers
                    )),
            InvalidPolicy()
        );

        IBondingRegistry currentBonding = bondingRegistry;
        require(address(currentBonding) != address(0), InvalidPolicy());
        uint64 assetVersion = currentBonding.bondingAssetConfigurationVersion();
        require(assetVersion != 0, InvalidPolicy());

        slashPolicies[reason] = policy;
        slashPolicyAssetContexts[reason] = SlashPolicyAssetContext(
            address(currentBonding),
            assetVersion
        );
        emit SlashPolicyUpdated(reason, policy);
    }

    /// @inheritdoc ISlashingManager
    function setBondingRegistry(
        IBondingRegistry newBondingRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(address(newBondingRegistry) != address(0), ZeroAddress());
        _requireGenerationDrained(address(bondingRegistry));
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
        _requireGenerationDrained(address(ciphernodeRegistry));
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
        _requireGenerationDrained(address(interfold));
        address oldValue = address(interfold);
        interfold = newInterfold;
        emit InterfoldUpdated(oldValue, address(newInterfold));
    }

    /// @inheritdoc ISlashingManager
    function setE3RefundManager(
        IE3RefundManager newRefundManager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(address(newRefundManager) != address(0), ZeroAddress());
        _requireGenerationDrained(address(e3RefundManager));
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
    ///      bytes evidence, uint256 issuedAt, uint256 deadline, bytes[] signatures)`.
    ///      Voters sign the EIP-712
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

        E3Dependencies memory dependencies = _dependenciesFor(e3Id);
        _requireCurrentPolicyAssetContext(reason, dependencies.bonding);
        require(
            dependencies.registry.isCommitteeMember(e3Id, operator),
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
        p.ciphernodeBondAmount = policy.ciphernodeBondPenalty;
        p.proposedAt = block.timestamp;
        p.executableAt = executableAt;
        p.proposer = msg.sender;
        p.proofHash = keccak256(proof);
        p.proofVerified = true;
        p.banNode = policy.banNode;
        p.affectsCommittee = policy.affectsCommittee;
        p.failureReason = policy.affectsCommittee
            ? uint8(IInterfold.FailureReason.InsufficientCommitteeMembers)
            : 0;

        _openProposal(p, proposalId);

        emit SlashProposed(
            proposalId,
            e3Id,
            operator,
            reason,
            policy.ticketPenalty,
            policy.ciphernodeBondPenalty,
            executableAt,
            msg.sender,
            Lane.LaneA
        );

        // Legacy atomic path: when no challenge window is configured, execute now.
        // Otherwise defer to `executeSlash` after `executableAt`.
        if (policy.appealWindow == 0) {
            _closeProposalCount(p);
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
        E3Dependencies memory dependencies = _dependenciesFor(e3Id);
        _requireCurrentPolicyAssetContext(reason, dependencies.bonding);
        require(
            dependencies.registry.isCommitteeMember(e3Id, operator),
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

        uint256 executableAt = block.timestamp + policy.appealWindow;
        SlashProposal storage p = _proposals[proposalId];
        p.e3Id = e3Id;
        p.operator = operator;
        p.reason = reason;
        p.ticketAmount = policy.ticketPenalty;
        p.ciphernodeBondAmount = policy.ciphernodeBondPenalty;
        p.proposedAt = block.timestamp;
        p.executableAt = executableAt;
        p.proposer = msg.sender;
        p.proofHash = keccak256(evidence);
        // Snapshot behavioral flags from policy at proposal time
        // to prevent execution drift if policy is modified during appeal window
        p.banNode = policy.banNode;
        p.affectsCommittee = policy.affectsCommittee;
        p.failureReason = policy.affectsCommittee
            ? uint8(IInterfold.FailureReason.InsufficientCommitteeMembers)
            : 0;

        _openProposal(p, proposalId);

        emit SlashProposed(
            proposalId,
            e3Id,
            operator,
            reason,
            policy.ticketPenalty,
            policy.ciphernodeBondPenalty,
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
        // Keep the registry lock until every slash side effect has completed.
        // This local count is only the manager's observable proposal state.
        _closeProposalCount(p);

        _executeSlash(proposalId, lane);
    }

    // ======================
    // Internal Execution
    // ======================

    /// @dev Mirror of `_openProposal` for the two counts. Every terminal path
    ///      calls this exactly once: atomic execution, deferred execution, an
    ///      upheld appeal, and an expired appeal.
    function _closeProposalCount(SlashProposal storage proposal) internal {
        _openProposalCount[proposal.operator] -= 1;
        if (proposal.affectsCommittee)
            _openCommitteeProposals[proposal.e3Id] -= 1;
    }

    function _openProposal(
        SlashProposal storage proposal,
        uint256 proposalId
    ) internal {
        E3Dependencies memory dependencies = _dependenciesFor(proposal.e3Id);
        _openProposalCount[proposal.operator]++;
        if (proposal.affectsCommittee) _openCommitteeProposals[proposal.e3Id]++;
        dependencies.bonding.openSlashLock(
            proposal.e3Id,
            proposalId,
            proposal.operator
        );
        if (proposal.affectsCommittee) {
            dependencies.refundManager.openExpulsionProposal(
                proposal.e3Id,
                proposalId,
                proposal.operator
            );
        }
    }

    /// @dev Verifies Lane A attestation evidence: decodes, checks quorum (>= M), verifies
    ///      each EIP-712 `AccusationVote` signature, confirms voters are active committee
    ///      members, enforces the shared issue time and deadline, and rejects equivocation
    ///      (all `dataHash` values must match and bind to `keccak256(evidence)`).
    ///      Voters must be sorted ascending (no duplicates).
    function _verifyAttestationEvidence(
        bytes calldata proof,
        uint256 e3Id,
        address operator
    ) internal view {
        E3Dependencies memory dependencies = _dependenciesFor(e3Id);
        SlashingEvidenceLib.verifyAttestationEvidence(
            proof,
            e3Id,
            operator,
            address(dependencies.registry),
            dependencies.accusationVoteValidity,
            dependencies.slashSubmissionDeadline,
            _domainSeparatorV4()
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
        uint256 actualCiphernodeBondSlashed = 0;

        // Execute financial penalties
        if (p.ticketAmount > 0) {
            actualTicketSlashed = dependencies.bonding.slashTicketBalance(
                p.operator,
                p.ticketAmount,
                p.reason
            );
        }

        if (p.ciphernodeBondAmount > 0) {
            actualCiphernodeBondSlashed = dependencies
                .bonding
                .slashCiphernodeBond(
                    p.operator,
                    p.ciphernodeBondAmount,
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
            _setBan(
                dependencies.bonding,
                p.operator,
                true,
                p.reason,
                address(this)
            );
        }

        // Committee expulsion for E3-scoped slashes (uses snapshotted behavioral flags)
        // expelCommitteeMember returns (activeCount, thresholdM) — one call instead of three
        if (p.affectsCommittee) {
            (uint256 activeCount, uint32 thresholdM) = dependencies
                .registry
                .expelCommitteeMember(p.e3Id, p.operator, p.reason);

            if (activeCount < thresholdM) {
                IInterfold.E3Stage stage = dependencies
                    .interfoldContract
                    .getE3Stage(p.e3Id);
                if (stage != IInterfold.E3Stage.Complete) {
                    // A nonterminal round fails here. A round that a caller
                    // already failed gets its requester-paid reason corrected,
                    // because this expulsion is the true cause (ZEN2-04).
                    // Interfold treats a correction that no longer applies as a
                    // no-op, so this call reverts only on a real fault, and a
                    // revert rolls back the penalties, ban, and committee
                    // membership change.
                    dependencies.interfoldContract.onE3Failed(
                        p.e3Id,
                        uint8(
                            IInterfold
                                .FailureReason
                                .InsufficientCommitteeMembers
                        )
                    );
                }
            }
            dependencies.refundManager.resolveExpulsionProposal(
                p.e3Id,
                proposalId,
                true
            );
        }

        // Reserve and attempt escrow. Failure leaves both a durable proposal
        // route and a matching BondingRegistry reservation for permissionless retry.
        if (actualTicketSlashed > 0) {
            PendingSlashRoute storage route = _pendingSlashRoutes[proposalId];
            route.e3Id = p.e3Id;
            route.token = address(
                dependencies.bonding.ticketToken().underlying()
            );
            route.amount = actualTicketSlashed;
            route.pending = true;
            route.operator = p.operator;
            dependencies.bonding.reserveSlashedTicketFunds(
                proposalId,
                p.e3Id,
                actualTicketSlashed
            );
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

        dependencies.bonding.closeSlashLock(proposalId, p.operator);

        emit SlashExecuted(
            proposalId,
            p.e3Id,
            p.operator,
            p.reason,
            actualTicketSlashed,
            actualCiphernodeBondSlashed,
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
        dependencies.bonding.redirectReservedSlashedTicketFunds(proposalId);
        dependencies.interfoldContract.escrowSlashedFunds(
            route.e3Id,
            proposalId,
            route.operator,
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
    /// @dev Appeals are permitted for proof-verified (Lane A) proposals when their
    ///      policy is configured with a non-zero `appealWindow`.
    function fileAppeal(uint256 proposalId, string calldata evidence) external {
        require(proposalId < totalProposals, InvalidProposal());
        SlashProposal storage p = _proposals[proposalId];

        // The accused operator or the owner whose collateral is at risk may appeal.
        address bondOwner = _e3Dependencies[p.e3Id].bonding.bondOwnerOf(
            p.operator
        );
        require(
            msg.sender == p.operator || msg.sender == bondOwner,
            Unauthorized()
        );
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
            E3Dependencies memory dependencies = _dependenciesFor(p.e3Id);
            if (p.affectsCommittee) {
                dependencies.refundManager.resolveExpulsionProposal(
                    p.e3Id,
                    proposalId,
                    false
                );
            }
            _closeProposalCount(p);
            dependencies.bonding.closeSlashLock(proposalId, p.operator);
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
        E3Dependencies memory dependencies = _dependenciesFor(p.e3Id);
        if (p.affectsCommittee) {
            dependencies.refundManager.resolveExpulsionProposal(
                p.e3Id,
                proposalId,
                false
            );
        }
        _closeProposalCount(p);
        dependencies.bonding.closeSlashLock(proposalId, p.operator);

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
        _setBan(bondingRegistry, node, true, reason, msg.sender);
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
        if (_pendingBans[node].proposer != address(0)) {
            delete _pendingBans[node];
            emit BanCancelled(node, msg.sender);
        }
        _setBan(bondingRegistry, node, false, reason, msg.sender);
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
        if (_pendingBans[node].proposer != address(0)) {
            delete _pendingBans[node];
            emit BanCancelled(node, msg.sender);
        }
        _setBan(bondingRegistry, node, false, reason, msg.sender);
    }

    /// @dev Mirror manager ban state into the registry that owns exit eligibility.
    function _setBan(
        IBondingRegistry registry,
        address operator,
        bool status,
        bytes32 reason,
        address updater
    ) internal {
        bool previous = banned[operator];
        banned[operator] = status;
        if (previous != status) {
            if (status) activeBanCount++;
            else activeBanCount--;
        }
        registry.setOperatorBan(operator, status);
        emit NodeBanUpdated(operator, status, reason, updater);
    }

    function _requireCurrentPolicyAssetContext(
        bytes32 reason,
        IBondingRegistry e3Bonding
    ) private view {
        SlashPolicyAssetContext memory context = slashPolicyAssetContexts[
            reason
        ];
        if (
            context.bondingRegistry != address(e3Bonding) ||
            context.configurationVersion == 0 ||
            context.configurationVersion !=
            e3Bonding.bondingAssetConfigurationVersion()
        ) revert SlashPolicyAssetConfigurationMismatch(reason);
    }

    function _requireGenerationDrained(address current) private view {
        if (
            current != address(0) &&
            (activeE3Assignments != 0 || activeBanCount != 0)
        ) revert InvalidProposal();
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
