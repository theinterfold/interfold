// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { IBondOwnerHistory } from "../interfaces/IBondOwnerHistory.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { IRandomnessProvider } from "../interfaces/IRandomnessProvider.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";
import {
    IProtocolDependencyView
} from "../interfaces/IProtocolDependencyView.sol";
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Resolves entropy and updates candidate rankings for registry sortition.
library RegistrySortitionLib {
    // keccak256(abi.encode(uint256(keccak256(namespace)) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant RANDOMNESS_STORAGE_SLOT =
        0x57a1af54ea0bbeb06d6edf6fa5ea97cbfa420879daa9f127d968d8e1bc60f000;

    uint256 private constant MIN_RANDOMNESS_REQUEST_TIMEOUT = 60;
    uint256 private constant MAX_RANDOMNESS_REQUEST_TIMEOUT = 1 days;
    uint256 private constant MAX_COMMITTEE_PUBLIC_KEY_BYTES = 512 * 1024;
    uint256 private constant MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES = 90 * 1024;
    uint256 private constant DEPENDENCY_PROBE_GAS = 100_000;

    /// @notice Validates an operator-preserving slashing-manager migration.
    /// @dev The registry and bonding contracts stay in place. Only service
    ///      dependencies can change through this path.
    function validateSlashingManagerMigration(
        address candidateAddress,
        address currentAddress,
        address controllerAddress,
        address bondingAddress,
        uint256 unreleasedCommittees
    ) external view {
        ISlashingManager candidate = ISlashingManager(candidateAddress);
        ISlashingManager current = ISlashingManager(currentAddress);
        IInterfold controller = IInterfold(controllerAddress);
        IBondingRegistry bonding = IBondingRegistry(bondingAddress);
        if (
            candidateAddress == currentAddress ||
            candidateAddress.code.length == 0 ||
            !_supportsSlashingManager(candidateAddress) ||
            !_usesSlashingManagerApiV1(candidateAddress)
        ) {
            revert ICiphernodeRegistry.IncompatibleSlashingManager(
                candidateAddress
            );
        }
        if (!controller.requestsPaused()) {
            revert ICiphernodeRegistry
                .ServiceDependencyMigrationRequiresPause();
        }
        if (
            controller.activeE3Count() != 0 ||
            unreleasedCommittees != 0 ||
            bonding.unresolvedCommitteeCount() != 0 ||
            current.activeE3Assignments() != 0 ||
            current.activeBanCount() != 0 ||
            candidate.activeE3Assignments() != 0 ||
            candidate.activeBanCount() != 0
        ) {
            revert ICiphernodeRegistry.ServiceDependencyMigrationNotDrained();
        }
        IProtocolDependencyView candidateView = IProtocolDependencyView(
            candidateAddress
        );
        if (
            candidateView.interfold() != controllerAddress ||
            candidateView.bondingRegistry() != bondingAddress ||
            candidateView.ciphernodeRegistry() != address(this) ||
            candidateView.e3RefundManager() !=
            IProtocolDependencyView(controllerAddress).e3RefundManager() ||
            address(controller.slashingManager()) != candidateAddress ||
            IProtocolDependencyView(bondingAddress).slashingManager() !=
            candidateAddress
        ) {
            revert ICiphernodeRegistry.IncompatibleSlashingManager(
                candidateAddress
            );
        }
    }

    function _supportsSlashingManager(
        address candidate
    ) private view returns (bool) {
        (bool ok, bytes memory result) = candidate.staticcall{
            gas: DEPENDENCY_PROBE_GAS
        }(
            abi.encodeCall(
                IERC165.supportsInterface,
                (type(ISlashingManager).interfaceId)
            )
        );
        return ok && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    function _usesSlashingManagerApiV1(
        address candidate
    ) private view returns (bool) {
        (bool ok, bytes memory result) = candidate.staticcall{
            gas: DEPENDENCY_PROBE_GAS
        }(abi.encodeCall(ISlashingManager.SLASHING_MANAGER_API_VERSION, ()));
        return ok && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    /// @notice Validates and emits one deterministic public-key chunk from registry storage.
    /// @dev This external library call runs with `delegatecall`, so the registry proxy remains
    ///      the event emitter and the original publisher remains `msg.sender`.
    function publishCommitteePublicKeyChunk(
        mapping(uint256 e3Id => ICiphernodeRegistry.Committee committee)
            storage committees,
        mapping(uint256 e3Id => bytes32 publicKeyHash) storage publicKeyHashes,
        uint256 e3Id,
        bytes32 candidateHash,
        uint16 chunkIndex,
        uint16 chunkCount,
        uint32 totalLength,
        bytes calldata chunk
    ) external {
        _requirePublicKeyPublicationOpen(e3Id);
        ICiphernodeRegistry.Committee storage committee = committees[e3Id];
        bytes32 pkCommitment = publicKeyHashes[e3Id];
        if (pkCommitment == bytes32(0))
            revert ICiphernodeRegistry.CommitteeNotPublished();
        if (
            candidateHash == bytes32(0) ||
            totalLength == 0 ||
            totalLength > MAX_COMMITTEE_PUBLIC_KEY_BYTES ||
            chunkCount == 0 ||
            chunkIndex >= chunkCount
        ) revert ICiphernodeRegistry.InvalidPublicKeyChunk();

        uint256 expectedChunkCount = (uint256(totalLength) +
            MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES -
            1) / MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES;
        if (chunkCount != expectedChunkCount)
            revert ICiphernodeRegistry.InvalidPublicKeyChunk();

        uint256 remaining = uint256(totalLength) -
            uint256(chunkIndex) *
            MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES;
        uint256 expectedLength = remaining >
            MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES
            ? MAX_COMMITTEE_PUBLIC_KEY_CHUNK_BYTES
            : remaining;
        if (chunk.length != expectedLength)
            revert ICiphernodeRegistry.InvalidPublicKeyChunk();
        if (
            committee.memberStatus[msg.sender] ==
            ICiphernodeRegistry.MemberStatus.None
        ) revert ICiphernodeRegistry.PublicKeyPublisherNotCommitteeMember();

        emit ICiphernodeRegistry.CommitteePublicKeyChunkPublished(
            e3Id,
            msg.sender,
            candidateHash,
            committee.topNodes,
            pkCommitment,
            chunkIndex,
            chunkCount,
            totalLength,
            chunk
        );
    }

    function _requirePublicKeyPublicationOpen(uint256 e3Id) private view {
        // Interfold embeds its proxy address in the high 160 bits of every E3 ID. Use that frozen
        // controller instead of the Registry's current dependency generation.
        IInterfold interfold = IInterfold(address(uint160(e3Id >> 96)));
        IInterfold.E3Stage stage = interfold.getE3Stage(e3Id);
        if (stage != IInterfold.E3Stage.KeyPublished) {
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.KeyPublished,
                stage
            );
        }
    }

    struct RandomnessRequest {
        IRandomnessProvider provider;
        uint256 requestId;
        uint256 requestedBlock;
        uint256 requestedAt;
        uint256 randomnessDeadline;
        uint256 submissionWindow;
        // Appended: requests created before this upgrade retain uncapped selection.
        bool bondOwnerCap;
    }

    /// @custom:storage-location erc7201:interfold.storage.RegistrySortitionRandomness
    /// @dev New fields are appended. Do not reorder existing fields.
    struct RandomnessStorage {
        IRandomnessProvider provider;
        uint256 requestTimeout;
        mapping(uint256 e3Id => RandomnessRequest request) requests;
        bool degraded;
        mapping(uint256 e3Id => mapping(address owner => address candidate)) ownerCandidates;
    }

    function insertCandidate(
        ICiphernodeRegistry.Committee storage committee,
        IBondingRegistry bondingRegistry,
        uint256 e3Id,
        address node,
        uint256 score
    ) external {
        RandomnessStorage storage state = _randomnessStorage();
        bool ownerCap = state.requests[e3Id].bondOwnerCap;
        address bondOwner;
        address sameOwnerCandidate;
        if (ownerCap) {
            bondOwner = IBondOwnerHistory(address(bondingRegistry)).bondOwnerAt(
                node,
                committee.requestBlock - 1
            );
            if (bondOwner == address(0))
                revert ICiphernodeRegistry.NodeNotEligible();
            sameOwnerCandidate = state.ownerCandidates[e3Id][bondOwner];
        }

        (bool inserted, address displaced) = _selectCandidate(
            committee,
            node,
            score,
            sameOwnerCandidate,
            ownerCap
        );
        if (!inserted) return;

        committee.scoreOf[node] = score;
        if (ownerCap) {
            if (displaced != address(0)) {
                address displacedOwner = IBondOwnerHistory(
                    address(bondingRegistry)
                ).bondOwnerAt(displaced, committee.requestBlock - 1);
                delete state.ownerCandidates[e3Id][displacedOwner];
            }
            state.ownerCandidates[e3Id][bondOwner] = node;
        }
        bondingRegistry.setCommitteeObligation(e3Id, node, true);
        if (displaced != address(0)) {
            bondingRegistry.setCommitteeObligation(e3Id, displaced, false);
        }
    }

    function _selectCandidate(
        ICiphernodeRegistry.Committee storage committee,
        address node,
        uint256 score,
        address sameOwnerCandidate,
        bool ownerCap
    ) private returns (bool inserted, address displaced) {
        address[] storage top = committee.topNodes;
        if (sameOwnerCandidate != address(0)) {
            if (
                !_ranksBefore(
                    score,
                    node,
                    committee.scoreOf[sameOwnerCandidate],
                    sameOwnerCandidate
                )
            ) return (false, address(0));
            for (uint256 i; i < top.length; ++i) {
                if (top[i] == sameOwnerCandidate) {
                    top[i] = node;
                    break;
                }
            }
            displaced = sameOwnerCandidate;
        } else if (top.length < committee.threshold[1]) {
            top.push(node);
        } else {
            uint256 worstIndex = _worstCandidateIndex(committee, ownerCap);
            uint256 worstScore = committee.scoreOf[top[worstIndex]];
            bool replaces = ownerCap
                ? _ranksBefore(score, node, worstScore, top[worstIndex])
                : score < worstScore;
            if (!replaces) return (false, address(0));
            displaced = top[worstIndex];
            top[worstIndex] = node;
        }

        return (true, displaced);
    }

    function _worstCandidateIndex(
        ICiphernodeRegistry.Committee storage committee,
        bool ownerCap
    ) private view returns (uint256 worstIndex) {
        address[] storage top = committee.topNodes;
        uint256 worstScore = committee.scoreOf[top[0]];
        for (uint256 i = 1; i < top.length; ++i) {
            uint256 candidateScore = committee.scoreOf[top[i]];
            if (
                candidateScore > worstScore ||
                (ownerCap &&
                    candidateScore == worstScore &&
                    top[i] > top[worstIndex])
            ) {
                worstScore = candidateScore;
                worstIndex = i;
            }
        }
    }

    function _ranksBefore(
        uint256 score,
        address node,
        uint256 otherScore,
        address otherNode
    ) private pure returns (bool) {
        return score < otherScore || (score == otherScore && node < otherNode);
    }

    /// @notice Validates every guard on one ticket submission.
    /// @dev One entry point so the registry pays one argument encoding instead
    ///      of five revert encodings. Revert precedence matches the previous
    ///      inline order exactly.
    /// @param c The committee the ticket targets.
    /// @param bondingRegistry The E3's request-time bonding registry.
    /// @param enabled Whether the registry lists the node as enabled.
    /// @param node The submitting node.
    /// @param ticketNumber The one-based ticket the node claims.
    /// @param ticketPrice The ticket price frozen at request.
    function validateTicket(
        ICiphernodeRegistry.Committee storage c,
        IBondingRegistry bondingRegistry,
        bool enabled,
        address node,
        uint256 ticketNumber,
        uint256 ticketPrice
    ) external view {
        if (block.timestamp > c.committeeDeadline)
            revert ICiphernodeRegistry.CommitteeDeadlineReached();
        if (c.submitted[node])
            revert ICiphernodeRegistry.NodeAlreadySubmitted();
        uint256 snapshotBlock = c.requestBlock - 1;
        if (!enabled || !_eligibleAt(bondingRegistry, node, snapshotBlock))
            revert ICiphernodeRegistry.NodeNotEligible();
        if (ticketNumber == 0 || ticketPrice == 0)
            revert ICiphernodeRegistry.InvalidTicketNumber();
        if (address(bondingRegistry) == address(0))
            revert ICiphernodeRegistry.BondingRegistryNotSet();
        uint256 availableTickets = bondingRegistry.ticketToken().getPastVotes(
            node,
            snapshotBlock
        ) / ticketPrice;
        if (availableTickets == 0) revert ICiphernodeRegistry.NodeNotEligible();
        if (ticketNumber > availableTickets)
            revert ICiphernodeRegistry.InvalidTicketNumber();
    }

    function _eligibleAt(
        IBondingRegistry bondingRegistry,
        address node,
        uint256 snapshotBlock
    ) private view returns (bool) {
        (bool activeAtRequest, ) = bondingRegistry.eligibilityAt(
            node,
            snapshotBlock
        );
        return bondingRegistry.isActive(node) && activeAtRequest;
    }

    function ticketScore(
        address node,
        uint256 ticketNumber,
        uint256 e3Id,
        uint256 seed
    ) external pure returns (uint256) {
        return
            uint256(
                keccak256(abi.encodePacked(node, ticketNumber, e3Id, seed))
            );
    }

    /// @notice Sorts selected nodes into the canonical address order.
    function sortTopNodes(
        ICiphernodeRegistry.Committee storage committee
    ) external {
        uint256 length = committee.topNodes.length;
        for (uint256 i = 0; i < length; ++i) {
            for (uint256 j = i + 1; j < length; ++j) {
                address left = committee.topNodes[i];
                address right = committee.topNodes[j];
                if (right < left) {
                    committee.topNodes[i] = right;
                    committee.topNodes[j] = left;
                }
            }
        }
    }

    /// @notice Returns active nodes and their frozen sortition scores.
    function activeCommitteeNodes(
        ICiphernodeRegistry.Committee storage committee
    ) external view returns (address[] memory nodes, uint256[] memory scores) {
        if (committee.stage != ICiphernodeRegistry.CommitteeStage.Finalized)
            return (new address[](0), new uint256[](0));

        uint256 total = committee.topNodes.length;
        uint256 activeCount;
        for (uint256 i = 0; i < total; ++i) {
            if (
                committee.memberStatus[committee.topNodes[i]] ==
                ICiphernodeRegistry.MemberStatus.Active
            ) activeCount++;
        }

        nodes = new address[](activeCount);
        scores = new uint256[](activeCount);
        uint256 outputIndex;
        for (uint256 i = 0; i < total; ++i) {
            address node = committee.topNodes[i];
            if (
                committee.memberStatus[node] ==
                ICiphernodeRegistry.MemberStatus.Active
            ) {
                nodes[outputIndex] = node;
                scores[outputIndex] = committee.scoreOf[node];
                outputIndex++;
            }
        }
    }

    /// @notice Returns DKG anchors after publication.
    function dkgAnchors(
        bool published,
        uint256[] storage partyIds,
        bytes32[] storage skAggCommits,
        bytes32[] storage esmAggCommits
    )
        external
        pure
        returns (uint256[] memory, bytes32[] memory, bytes32[] memory)
    {
        if (!published) revert ICiphernodeRegistry.CommitteeNotPublished();
        return (partyIds, skAggCommits, esmAggCommits);
    }

    /// @notice Resolves one request-bound VRF result and its ticket deadline.
    /// @dev A timely result remains readable after terminal cleanup so historical replay derives
    ///      the same committee request. A late result still fails response validation.
    function sortitionState(
        uint256 e3Id,
        bool seedResolved,
        uint256 storedSeed,
        uint256 storedDeadline
    )
        external
        view
        returns (bool ready, uint256 seed, uint256 committeeDeadline)
    {
        if (seedResolved) {
            return (true, storedSeed, storedDeadline);
        }
        RandomnessRequest storage request = _randomnessStorage().requests[e3Id];
        if (request.requestId == 0 || address(request.provider) == address(0)) {
            return (false, 0, request.randomnessDeadline);
        }
        return _providerState(request, e3Id);
    }

    function _providerState(
        RandomnessRequest storage request,
        uint256 e3Id
    )
        private
        view
        returns (bool ready, uint256 seed, uint256 committeeDeadline)
    {
        try request.provider.getRandomness(request.requestId) returns (
            bool fulfilled,
            uint256 randomWord,
            uint256 fulfilledAt,
            uint256 fulfilledBlock
        ) {
            if (
                !_isUsableResponse(
                    request,
                    fulfilled,
                    fulfilledAt,
                    fulfilledBlock
                )
            ) return (false, 0, request.randomnessDeadline);

            committeeDeadline = fulfilledAt + request.submissionWindow;
            seed = _deriveSeed(randomWord, e3Id, request.requestId);
            return (true, seed, committeeDeadline);
        } catch {
            return (false, 0, request.randomnessDeadline);
        }
    }

    /// @notice Requests and freezes randomness configuration for one E3.
    function requestRandomness(
        uint256 e3Id,
        uint256 submissionWindow,
        IBondOwnerHistory bondingHistory,
        uint256 requiredOwners
    ) external returns (uint256 requestId, uint256 randomnessDeadline) {
        RandomnessStorage storage state = _randomnessStorage();
        IRandomnessProvider provider = state.provider;
        if (address(provider) == address(0))
            revert ICiphernodeRegistry.ZeroAddress();
        uint256 timeout = state.requestTimeout;
        if (timeout == 0)
            revert ICiphernodeRegistry.RandomnessRequestTimeoutOutOfBounds(
                timeout
            );

        RandomnessRequest storage request = state.requests[e3Id];
        // Reject a partial deployment before the requester pays for a VRF draw.
        bondingHistory.bondOwnerAt(address(0), block.timestamp - 1);
        uint256 owners = bondingHistory.committeeOwnerCapacity(
            block.timestamp - 1
        );
        if (owners < requiredOwners)
            revert ICiphernodeRegistry.InsufficientBondOwners(
                requiredOwners,
                owners
            );
        request.bondOwnerCap = true;
        emit ICiphernodeRegistry.CommitteeBondOwnerCapEnabled(e3Id);
        request.provider = provider;
        request.submissionWindow = submissionWindow;
        request.requestedBlock = currentBlockNumber();
        request.requestedAt = block.timestamp;
        randomnessDeadline = block.timestamp + timeout;
        request.randomnessDeadline = randomnessDeadline;
        requestId = provider.requestRandomness(e3Id);
        if (requestId == 0)
            revert ICiphernodeRegistry.InvalidRandomnessRequestId();
        request.requestId = requestId;

        emit ICiphernodeRegistry.CommitteeRandomnessRequested(
            e3Id,
            requestId,
            address(provider),
            randomnessDeadline
        );
    }

    /// @notice Clears terminal candidates and marks an unfinalized committee as failed.
    /// @dev A timely response must never be discarded and replaced with a new draw.
    function releaseCommitteeCandidates(
        ICiphernodeRegistry.Committee storage committee,
        uint256 e3Id,
        IBondingRegistry bonding
    ) external {
        RandomnessStorage storage state = _randomnessStorage();
        if (state.requests[e3Id].bondOwnerCap) {
            for (uint256 i = 0; i < committee.topNodes.length; ++i) {
                address owner = IBondOwnerHistory(address(bonding)).bondOwnerAt(
                    committee.topNodes[i],
                    committee.requestBlock - 1
                );
                delete state.ownerCandidates[e3Id][owner];
            }
        }
        if (committee.stage != ICiphernodeRegistry.CommitteeStage.Requested)
            return;
        _flagRandomnessDegraded(e3Id);
        committee.stage = ICiphernodeRegistry.CommitteeStage.Failed;
    }

    /// @notice Reports one expired randomness response without stopping new requests.
    /// @dev The breaker is advisory. An expired response is reachable permissionlessly through
    ///      the committee timeout path, through `markE3Failed`, and through `cancelE3`. If it
    ///      cleared the registry-global provider, one prepared round could stop every later
    ///      request until governance pauses requests and every committee releases. This
    ///      function records the condition and lets governance re-point the provider.
    function _flagRandomnessDegraded(uint256 e3Id) private {
        RandomnessStorage storage state = _randomnessStorage();
        RandomnessRequest storage request = state.requests[e3Id];
        if (
            address(state.provider) == address(0) ||
            address(state.provider) != address(request.provider) ||
            request.requestId == 0 ||
            block.timestamp <= request.randomnessDeadline
        ) return;

        (bool ready, , ) = _providerState(request, e3Id);
        if (ready) return;

        if (!state.degraded) state.degraded = true;
        emit ICiphernodeRegistry.RandomnessCircuitBreakerTripped(
            e3Id,
            request.requestId,
            address(state.provider)
        );
    }

    /// @notice Validates every precondition for releasing a committee's obligations.
    /// @dev One entry point so the registry encodes one argument list instead of four separate
    ///      guards, each with its own revert data. A finalized committee did protocol work that
    ///      peers can still accuse, so its collateral stays held until the slashing manager
    ///      stops accepting accusations for the E3. A committee that never finalized has no
    ///      accusable work, so its candidates release at terminal stage. `closeE3` clears the
    ///      deadline only after it has passed, so a zero deadline also permits release.
    /// @param stage The committee's current stage.
    /// @param obligationsReleased Whether this committee already released.
    /// @param e3Stage The E3's current stage.
    /// @param slashingManager The slashing manager frozen for this E3.
    /// @param e3Id The E3 whose committee is being released.
    function validateCommitteeRelease(
        ICiphernodeRegistry.CommitteeStage stage,
        bool obligationsReleased,
        IInterfold.E3Stage e3Stage,
        ISlashingManager slashingManager,
        uint256 e3Id
    ) external view {
        if (
            stage != ICiphernodeRegistry.CommitteeStage.Requested &&
            stage != ICiphernodeRegistry.CommitteeStage.Finalized
        ) revert ICiphernodeRegistry.CommitteeNotFinalized();
        if (obligationsReleased)
            revert ICiphernodeRegistry.CommitteeObligationsAlreadyReleased(
                e3Id
            );
        if (
            e3Stage != IInterfold.E3Stage.Complete &&
            e3Stage != IInterfold.E3Stage.Failed
        ) revert ICiphernodeRegistry.E3NotTerminal(e3Id);
        if (stage != ICiphernodeRegistry.CommitteeStage.Finalized) return;
        uint64 submissionDeadline = slashingManager
            .accusationSubmissionDeadline(e3Id);
        if (block.timestamp <= submissionDeadline)
            revert ICiphernodeRegistry.CommitteeAccusationWindowOpen(
                e3Id,
                submissionDeadline
            );
    }

    /// @notice Sets the provider used by future requests.
    function setRandomnessProvider(
        IRandomnessProvider provider,
        uint256 unreleasedCommittees
    ) external {
        _requireRequestsPaused();
        if (unreleasedCommittees != 0)
            revert ICiphernodeRegistry.RandomnessConfigurationInUse(
                unreleasedCommittees
            );
        address providerAddress = address(provider);
        if (providerAddress.code.length == 0)
            revert ICiphernodeRegistry.InvalidRandomnessProvider(
                providerAddress
            );
        address actualRequester = provider.requester();
        if (actualRequester != address(this))
            revert ICiphernodeRegistry.RandomnessProviderRequesterMismatch(
                providerAddress,
                address(this),
                actualRequester
            );
        RandomnessStorage storage state = _randomnessStorage();
        state.provider = provider;
        // A new provider clears the advisory degraded flag.
        if (state.degraded) state.degraded = false;
        emit ICiphernodeRegistry.RandomnessProviderSet(providerAddress);
    }

    /// @notice Sets the maximum response wait for future requests.
    function setRandomnessRequestTimeout(
        uint256 timeout,
        uint256 unreleasedCommittees,
        uint256 submissionWindow,
        IBondingRegistry bondingRegistry
    ) external {
        _requireRequestsPaused();
        if (unreleasedCommittees != 0)
            revert ICiphernodeRegistry.RandomnessConfigurationInUse(
                unreleasedCommittees
            );
        if (
            timeout < MIN_RANDOMNESS_REQUEST_TIMEOUT ||
            timeout > MAX_RANDOMNESS_REQUEST_TIMEOUT
        )
            revert ICiphernodeRegistry.RandomnessRequestTimeoutOutOfBounds(
                timeout
            );
        if (address(bondingRegistry) != address(0)) {
            uint256 requiredDelay = timeout + submissionWindow;
            uint256 exitDelay = bondingRegistry.exitDelay();
            if (exitDelay <= requiredDelay)
                revert ICiphernodeRegistry.ExitDelayMustExceedSortitionWindow(
                    exitDelay,
                    requiredDelay
                );
        }
        _randomnessStorage().requestTimeout = timeout;
        emit ICiphernodeRegistry.RandomnessRequestTimeoutSet(timeout);
    }

    function randomnessProvider() external view returns (address) {
        return address(_randomnessStorage().provider);
    }

    function randomnessRequestTimeout() external view returns (uint256) {
        return _randomnessStorage().requestTimeout;
    }

    /// @notice Tells whether one randomness response expired since the last provider change.
    function randomnessDegraded() external view returns (bool) {
        return _randomnessStorage().degraded;
    }

    function requestContext(
        uint256 e3Id
    )
        external
        view
        returns (
            address provider,
            uint256 requestId,
            uint256 randomnessDeadline
        )
    {
        RandomnessRequest storage request = _randomnessStorage().requests[e3Id];
        return (
            address(request.provider),
            request.requestId,
            request.randomnessDeadline
        );
    }

    /// @notice Returns the Ethereum block number used for request and fulfillment markers.
    function currentBlockNumber() internal view returns (uint256) {
        return block.number;
    }

    function _randomnessStorage()
        private
        pure
        returns (RandomnessStorage storage state)
    {
        bytes32 slot = RANDOMNESS_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            state.slot := slot
        }
    }

    function _deriveSeed(
        uint256 randomWord,
        uint256 e3Id,
        uint256 requestId
    ) private view returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encode(
                        randomWord,
                        block.chainid,
                        address(this),
                        e3Id,
                        requestId
                    )
                )
            );
    }

    function _isUsableResponse(
        RandomnessRequest storage request,
        bool fulfilled,
        uint256 fulfilledAt,
        uint256 fulfilledBlock
    ) private view returns (bool) {
        uint256 currentBlock = currentBlockNumber();
        return
            fulfilled &&
            fulfilledAt != 0 &&
            fulfilledAt >= request.requestedAt &&
            fulfilledAt <= block.timestamp &&
            fulfilledBlock > request.requestedBlock &&
            fulfilledBlock <= currentBlock &&
            fulfilledAt <= request.randomnessDeadline &&
            fulfilledAt <= type(uint256).max - request.submissionWindow;
    }

    function _requireRequestsPaused() private view {
        // The proxy has no runtime code while its constructor delegate-calls initialize.
        // No E3 request can reach it during that bootstrap phase.
        if (address(this).code.length == 0) return;
        IInterfold controller = ICiphernodeRegistry(address(this)).interfold();
        if (address(controller) != address(0) && !controller.requestsPaused()) {
            revert ICiphernodeRegistry.RandomnessConfigurationRequiresPause();
        }
    }
}
