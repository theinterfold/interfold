// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IInterfold } from "../interfaces/IInterfold.sol";
import { IE3Program } from "../interfaces/IE3Program.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IE3RefundManager } from "../interfaces/IE3RefundManager.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";
import { INodeReleaseRegistry } from "../interfaces/INodeReleaseRegistry.sol";
import {
    IProtocolDependencyView
} from "../interfaces/IProtocolDependencyView.sol";
import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";
import { IPkVerifier } from "../interfaces/IPkVerifier.sol";
import { ICiphertextVerifier } from "../interfaces/ICiphertextVerifier.sol";
import {
    IDataAvailabilityVerifier,
    IE3ProgramDataAvailability
} from "../interfaces/IDataAvailabilityVerifier.sol";
import { E3 } from "../interfaces/IE3.sol";
import {
    CiphertextVerifierStorage
} from "../storage/CiphertextVerifierStorage.sol";
import { ActiveCryptoConfig } from "./ActiveCryptoConfig.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title InterfoldLifecycle
 * @notice Contains stateless E3 lifecycle validation and proof helpers.
 * @dev External calls use DELEGATECALL. This keeps the Interfold proxy as the
 *      execution context and keeps lifecycle code out of its runtime bytecode.
 */
library InterfoldLifecycle {
    // keccak256(abi.encode(uint256(keccak256("interfold.storage.CiphertextVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant CIPHERTEXT_VERIFIER_STORAGE_SLOT =
        0xfc399dd26441dab88259cd69fffcf8b5f96dd87f2db63f29285d86101a4d1500;

    /// @notice Closes new request admission for one program.
    /// @dev Existing E3 records keep their request-time program address.
    function unregisterE3Program(
        mapping(IE3Program => bool) storage programs,
        IE3Program e3Program
    ) external {
        if (!programs[e3Program])
            revert IInterfold.E3ProgramNotAllowed(e3Program);
        programs[e3Program] = false;
        emit IInterfold.E3ProgramUnregistered(e3Program);
    }

    /// @notice Checks the fee and circuit values accepted with a quote.
    function validateQuoteLimit(
        address actualFeeToken,
        address expectedFeeToken,
        uint8 paramSet,
        bytes32 expectedCryptoConfigId,
        uint256 maxFee,
        uint256 fee
    ) external pure {
        if (actualFeeToken != expectedFeeToken)
            revert IInterfold.FeeTokenChanged(
                IERC20(expectedFeeToken),
                IERC20(actualFeeToken)
            );
        bytes32 configId = ActiveCryptoConfig.configIdForParamSet(paramSet);
        if (expectedCryptoConfigId != configId)
            revert IInterfold.CryptoConfigChanged(
                expectedCryptoConfigId,
                configId
            );
        if (fee > maxFee) revert IInterfold.FeeExceedsMaximum(fee, maxFee);
    }

    /// @notice Binds an E3 to the circuit and parameter bytes used at request time.
    function bindCryptoConfig(
        uint256 e3Id,
        bytes32 encryptionSchemeId,
        bytes calldata encodedParams
    ) external {
        ActiveCryptoConfig.validateEncryptionScheme(encryptionSchemeId);
        bytes32 paramsHash = keccak256(encodedParams);
        CiphertextVerifierStorage.Layout
            storage state = _ciphertextVerifierLayout();
        ICiphertextVerifier verifier = state.current[encryptionSchemeId];
        if (address(verifier) == address(0))
            revert IInterfold.InvalidEncryptionScheme(encryptionSchemeId);
        state.requests[e3Id] = CiphertextVerifierStorage.RequestConfig(
            verifier,
            paramsHash
        );
    }

    /// @notice Rejects requests unless every dependency points to one graph.
    function validateDependencyGraph(
        address registryAddress,
        address bondingAddress,
        address slashManagerAddress,
        address refundManagerAddress,
        address nodeReleaseRegistryAddress
    ) external view {
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        IBondingRegistry bonding = IBondingRegistry(bondingAddress);
        IProtocolDependencyView registryView = IProtocolDependencyView(
            registryAddress
        );
        IProtocolDependencyView bondingView = IProtocolDependencyView(
            bondingAddress
        );
        IProtocolDependencyView slashView = IProtocolDependencyView(
            slashManagerAddress
        );
        IProtocolDependencyView refundView = IProtocolDependencyView(
            refundManagerAddress
        );
        INodeReleaseRegistry nodeReleaseRegistry = INodeReleaseRegistry(
            nodeReleaseRegistryAddress
        );
        if (
            registryAddress.code.length == 0 ||
            bondingAddress.code.length == 0 ||
            slashManagerAddress.code.length == 0 ||
            refundManagerAddress.code.length == 0 ||
            nodeReleaseRegistryAddress.code.length == 0 ||
            registryView.interfold() != address(this) ||
            registryView.bondingRegistry() != bondingAddress ||
            registryView.slashingManager() != slashManagerAddress ||
            bondingView.registry() != registryAddress ||
            bondingView.slashingManager() != slashManagerAddress ||
            address(bonding.ticketToken().registry()) != bondingAddress ||
            slashView.interfold() != address(this) ||
            slashView.ciphernodeRegistry() != registryAddress ||
            slashView.bondingRegistry() != bondingAddress ||
            slashView.e3RefundManager() != refundManagerAddress ||
            refundView.interfold() != address(this) ||
            refundView.bondingRegistry() != bondingAddress ||
            address(nodeReleaseRegistry.bondingRegistry()) != bondingAddress ||
            address(nodeReleaseRegistry.ciphernodeRegistry()) !=
            registryAddress ||
            registry.numCiphernodes() != bonding.numRegisteredOperators()
        ) revert IInterfold.DependencyConfigurationMismatch();
    }

    /// @notice Requires the current dependency generation to own no live state.
    function validateGenerationDrained(
        bool configurationActivated,
        bool requestsPaused,
        uint256 activeE3Count,
        address registryAddress,
        address bondingAddress,
        address slashManagerAddress,
        address replacementRegistryAddress
    ) external view {
        if (replacementRegistryAddress != address(0)) {
            ICiphernodeRegistry replacementRegistry = ICiphernodeRegistry(
                replacementRegistryAddress
            );
            if (
                replacementRegistry.numCiphernodes() != 0 ||
                replacementRegistry.unreleasedCommitteeCount() != 0
            ) revert IInterfold.DependencyGenerationNotDrained();
        }
        if (!configurationActivated) return;
        if (!requestsPaused) revert IInterfold.RequestsPaused();
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        IBondingRegistry bonding = IBondingRegistry(bondingAddress);
        ISlashingManager slashManager = ISlashingManager(slashManagerAddress);
        if (
            activeE3Count != 0 ||
            registry.unreleasedCommitteeCount() != 0 ||
            registry.numCiphernodes() != 0 ||
            bonding.unresolvedCommitteeCount() != 0 ||
            bonding.numRegisteredOperators() != 0 ||
            slashManager.activeE3Assignments() != 0 ||
            slashManager.activeBanCount() != 0
        ) revert IInterfold.DependencyGenerationNotDrained();
    }

    /// @notice Validates finalization and freezes committee reward recipients.
    function validateAndSnapshotCommitteeFinalization(
        address caller,
        address registryAddress,
        address refundManagerAddress,
        uint256 e3Id,
        uint8 current,
        uint256 dkgWindow
    ) external returns (uint256 dkgDeadline) {
        if (caller != registryAddress)
            revert IInterfold.OnlyCiphernodeRegistry();
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage != IInterfold.E3Stage.Requested)
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.Requested,
                stage
            );
        dkgDeadline =
            ICiphernodeRegistry(registryAddress).getCommitteeDeadline(e3Id) +
            dkgWindow;
        if (block.timestamp > dkgDeadline)
            revert IInterfold.DKGDeadlinePassed(e3Id, dkgDeadline);
        (address[] memory nodes, ) = ICiphernodeRegistry(registryAddress)
            .getActiveCommitteeNodes(e3Id);
        IE3RefundManager(refundManagerAddress).snapshotRewardRecipients(
            e3Id,
            nodes
        );
    }

    function validateSlashCaller(
        address caller,
        address slashManager
    ) external pure {
        require(caller == slashManager, IInterfold.OnlySlashingManager());
    }

    function validateRegistryOrSlashCaller(
        address caller,
        address registry,
        address slashManager
    ) external pure {
        require(
            caller == registry || caller == slashManager,
            IInterfold.OnlyCiphernodeRegistryOrSlashingManager()
        );
    }

    function verifyPlaintext(
        address verifierAddress,
        address registryAddress,
        uint256 e3Id,
        bytes32 ciphertextHash,
        bytes32 committeePublicKey,
        bytes32 plaintextHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view {
        _requireViableCommittee(registryAddress, e3Id);
        if (proof.length == 0) revert IInterfold.ProofRequired();
        bytes32 committeeHash = ICiphernodeRegistry(registryAddress)
            .getCommitteeHash(e3Id);
        bytes32 decryptionDomain = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                e3Id,
                committeeHash,
                ciphertextHash,
                committeePublicKey
            )
        );
        if (
            !IDecryptionVerifier(verifierAddress).verify(
                e3Id,
                decryptionDomain,
                plaintextHash,
                committeeHash,
                ciphertextCommitment,
                proof
            )
        ) revert IDecryptionVerifier.InvalidProof();
    }

    // prettier-ignore
    function validateCommitteePublication(
        address caller, address registry, uint256 e3Id, uint8 current, uint256 dkgDeadline
    ) external view {
        if (caller != registry) revert IInterfold.OnlyCiphernodeRegistry();
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage != IInterfold.E3Stage.CommitteeFinalized)
            revert IInterfold.InvalidStage(e3Id, IInterfold.E3Stage.CommitteeFinalized, stage);
        if (block.timestamp > dkgDeadline)
            revert IInterfold.DKGDeadlinePassed(e3Id, dkgDeadline);
    }

    /// @notice Validates, verifies, and records a content-addressed ciphertext output.
    /// @dev The availability adapter proves that the exact bytes named by
    ///      `ciphertextOutputHash` were published. The existing compute proof binds that same
    ///      hash and the ciphertext commitment to this E3.
    function publishCiphertext(
        mapping(uint256 e3Id => E3 e3) storage e3s,
        mapping(uint256 e3Id => IInterfold.E3Stage stage) storage stages,
        mapping(uint256 e3Id => IInterfold.E3Deadlines deadlines)
            storage deadlines,
        address registryAddress,
        uint256 e3Id,
        uint256 decryptionWindow,
        bytes calldata encodedOutputReference
    ) external {
        IInterfold.CiphertextOutputReference memory outputReference = abi
            .decode(
                encodedOutputReference,
                (IInterfold.CiphertextOutputReference)
            );
        bytes32 contentHash = outputReference.contentHash;
        bytes32 ciphertextCommitment = outputReference.ciphertextCommitment;
        E3 storage e3 = e3s[e3Id];
        _validateCiphertextReference(
            e3,
            stages[e3Id],
            deadlines[e3Id].computeDeadline,
            e3Id,
            contentHash
        );
        _requireViableCommittee(registryAddress, e3Id);

        IDataAvailabilityVerifier.DataReference
            memory availabilityReceipt = _verifyDataAvailability(
                address(e3.e3Program),
                contentHash,
                outputReference.availabilityProof
            );

        if (
            !_isValidCiphertextHash(
                e3,
                e3Id,
                contentHash,
                ciphertextCommitment,
                outputReference.computeProof
            )
        ) revert IInterfold.InvalidOutput(bytes(""));

        e3.ciphertextOutput = contentHash;
        e3.ciphertextCommitment = ciphertextCommitment;
        stages[e3Id] = IInterfold.E3Stage.CiphertextReady;
        deadlines[e3Id].decryptionDeadline = block.timestamp + decryptionWindow;

        emit IInterfold.CiphertextOutputReferencePublished(
            e3Id,
            contentHash,
            ciphertextCommitment,
            availabilityReceipt.blockNumber,
            availabilityReceipt.leafIndex
        );
        emit IInterfold.E3StageChanged(
            e3Id,
            IInterfold.E3Stage.KeyPublished,
            IInterfold.E3Stage.CiphertextReady
        );
    }

    function _validateCiphertextReference(
        E3 storage e3,
        IInterfold.E3Stage stage,
        uint256 computeDeadline,
        uint256 e3Id,
        bytes32 ciphertextOutputHash
    ) private view {
        if (address(e3.e3Program) == address(0))
            revert IInterfold.E3DoesNotExist(e3Id);
        if (stage != IInterfold.E3Stage.KeyPublished)
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.KeyPublished,
                stage
            );
        if (computeDeadline < block.timestamp)
            revert IInterfold.CommitteeDutiesCompleted(e3Id, computeDeadline);
        if (block.timestamp < e3.inputWindow[1])
            revert IInterfold.InputDeadlineNotReached(e3Id, e3.inputWindow[1]);
        if (e3.ciphertextOutput != bytes32(0))
            revert IInterfold.CiphertextOutputAlreadyPublished(e3Id);
        if (ciphertextOutputHash == bytes32(0))
            revert IInterfold.InvalidOutput(bytes(""));
    }

    function _verifyDataAvailability(
        address e3Program,
        bytes32 ciphertextOutputHash,
        bytes memory availabilityProof
    )
        private
        view
        returns (IDataAvailabilityVerifier.DataReference memory receipt)
    {
        receipt = IE3ProgramDataAvailability(e3Program).verifyDataAvailability(
            ciphertextOutputHash,
            availabilityProof
        );
        if (receipt.contentHash != ciphertextOutputHash)
            revert IInterfold.InvalidOutput(bytes(""));
    }

    /// @notice Sets the verifier used by future requests for one scheme.
    function setCiphertextVerifier(
        bytes32 encryptionSchemeId,
        ICiphertextVerifier verifier
    ) external {
        if (
            address(verifier).code.length == 0 ||
            _ciphertextVerifierLayout().current[encryptionSchemeId] == verifier
        ) revert IInterfold.InvalidEncryptionScheme(encryptionSchemeId);
        _ciphertextVerifierLayout().current[encryptionSchemeId] = verifier;
    }

    /// @notice Returns the verifier configured for future requests using one scheme.
    function getCiphertextVerifier(
        bytes32 encryptionSchemeId
    ) external view returns (address) {
        return address(_ciphertextVerifierLayout().current[encryptionSchemeId]);
    }

    /// @notice Freezes the configured verifier for an E3 request.
    function _isValidCiphertextHash(
        E3 storage e3,
        uint256 e3Id,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes memory proof
    ) private returns (bool) {
        CiphertextVerifierStorage.RequestConfig
            storage config = _ciphertextVerifierLayout().requests[e3Id];
        if (
            address(config.verifier) == address(0) ||
            !config.verifier.verify(
                e3Id,
                e3.encryptionSchemeId,
                config.paramsHash,
                e3.committeePublicKey,
                ciphertextOutputHash,
                ciphertextCommitment,
                proof
            )
        ) return false;
        return
            e3.e3Program.verify(
                e3Id,
                ciphertextOutputHash,
                ciphertextCommitment,
                proof
            );
    }

    function _requireViableCommittee(
        address registryAddress,
        uint256 e3Id
    ) private view {
        (, , , bool viable) = ICiphernodeRegistry(registryAddress)
            .getCommitteeViability(e3Id);
        require(viable, ICiphernodeRegistry.ThresholdNotMet());
    }

    function _ciphertextVerifierLayout()
        private
        pure
        returns (CiphertextVerifierStorage.Layout storage state)
    {
        bytes32 slot = CIPHERTEXT_VERIFIER_STORAGE_SLOT;
        assembly {
            state.slot := slot
        }
    }

    /// @notice Checks whether an E3 stage can enter the failure path.
    /// @param current The current E3 stage, encoded as `uint8`.
    function validateMarkFailedStage(
        uint256 e3Id,
        uint8 current
    ) external pure {
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage == IInterfold.E3Stage.None)
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.Requested,
                stage
            );
        if (stage == IInterfold.E3Stage.Complete)
            revert IInterfold.E3AlreadyComplete(e3Id);
        if (stage == IInterfold.E3Stage.Failed)
            revert IInterfold.E3AlreadyFailed(e3Id);
    }

    // prettier-ignore
    function validateReportedFailure(
        address caller, address registry, address slashManager, uint256 e3Id, uint8 current, uint8 reason
    ) external pure {
        if (caller != registry && caller != slashManager)
            revert IInterfold.OnlyCiphernodeRegistryOrSlashingManager();
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage == IInterfold.E3Stage.None)
            revert IInterfold.InvalidStage(e3Id, IInterfold.E3Stage.Requested, stage);
        if (stage == IInterfold.E3Stage.Complete)
            revert IInterfold.E3AlreadyComplete(e3Id);
        if (stage == IInterfold.E3Stage.Failed)
            revert IInterfold.E3AlreadyFailed(e3Id);
        if (
            reason == uint8(IInterfold.FailureReason.None) ||
            reason ==
            uint8(IInterfold.FailureReason.RequesterCancelled) ||
            reason >= uint8(IInterfold.FailureReason._MAX_FAILURE_REASON)
        ) revert IInterfold.InvalidFailureReason(reason);
    }

    function validateMarkFailedCaller(
        uint256 e3Id,
        uint256 deadline,
        uint256 grace,
        address caller,
        address requester,
        address contractOwner,
        address registry
    ) external view {
        if (grace == 0) return;
        uint256 graceEnds = deadline + grace;
        if (
            block.timestamp < graceEnds &&
            caller != requester &&
            caller != contractOwner &&
            !ICiphernodeRegistry(registry).isCommitteeMemberActive(e3Id, caller)
        ) revert IInterfold.MarkE3FailedInGracePeriod(e3Id, graceEnds);
    }

    // prettier-ignore
    function failureCondition(
        address registryAddress, uint256 e3Id, uint8 current,
        IInterfold.E3Deadlines calldata deadlines, uint256 dkgWindow
    ) external view returns (bool canFail, uint8 reason, uint256 deadline) {
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage == IInterfold.E3Stage.Requested) {
            ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
            deadline = registry.getCommitteeDeadline(e3Id);
            if (registry.committeeThresholdMet(e3Id)) {
                deadline += dkgWindow;
            }
            reason = uint8(
                IInterfold.FailureReason.CommitteeFormationTimeout
            );
        } else if (stage == IInterfold.E3Stage.CommitteeFinalized) {
            deadline = deadlines.dkgDeadline;
            reason = uint8(IInterfold.FailureReason.DKGTimeout);
        } else if (stage == IInterfold.E3Stage.KeyPublished) {
            deadline = deadlines.computeDeadline;
            reason = uint8(IInterfold.FailureReason.ComputeTimeout);
        } else if (stage == IInterfold.E3Stage.CiphertextReady) {
            deadline = deadlines.decryptionDeadline;
            reason = uint8(IInterfold.FailureReason.DecryptionTimeout);
        }

        canFail = deadline != 0 && block.timestamp > deadline;
        if (!canFail) reason = uint8(IInterfold.FailureReason.None);
    }

    /// @notice Checks the timeout configuration.
    function validateTimeoutConfig(
        IInterfold.E3TimeoutConfig calldata config,
        uint256 maxTimeoutWindow
    ) external pure {
        if (config.dkgWindow == 0 || config.dkgWindow > maxTimeoutWindow)
            revert IInterfold.InvalidTimeoutWindow();
        if (
            config.computeWindow == 0 || config.computeWindow > maxTimeoutWindow
        ) revert IInterfold.InvalidTimeoutWindow();
        if (
            config.decryptionWindow == 0 ||
            config.decryptionWindow > maxTimeoutWindow
        ) revert IInterfold.InvalidTimeoutWindow();
    }

    /// @notice Checks the committee threshold configuration.
    function validateCommitteeThresholds(
        uint8 committeeSize,
        uint32[2] calldata threshold,
        uint32 minCommitteeSize,
        uint32 minThreshold
    ) external pure {
        ActiveCryptoConfig.validateCommittee(committeeSize, threshold);
        if (minCommitteeSize > 0 && threshold[1] < minCommitteeSize)
            revert IInterfold.BelowMinCommitteeSize(
                threshold[1],
                minCommitteeSize
            );
        if (minThreshold > 0 && threshold[0] < minThreshold)
            revert IInterfold.BelowMinThreshold(threshold[0], minThreshold);
    }

    /// @notice Checks an append-only parameter-set registration.
    function validateParamSet(
        uint8 paramSet,
        bytes32 paramSetHash,
        bool alreadyRegistered
    ) external view {
        if (alreadyRegistered)
            revert IInterfold.ParamSetAlreadyRegistered(paramSet);
        ActiveCryptoConfig.validateParamSet(paramSet, paramSetHash);
    }

    /// @notice Checks that a PK verifier matches the active DKG circuit.
    function validatePkVerifier(address verifier) external view {
        if (verifier.code.length == 0)
            revert IInterfold.InvalidEncryptionScheme(bytes32(0));
        uint256 actual = IPkVerifier(verifier).h();
        uint256 expected = ActiveCryptoConfig.h();
        if (actual != expected)
            revert IInterfold.VerifierThresholdMismatch(actual, expected);
    }

    /// @notice Checks that a decryption verifier matches the active circuit.
    function validateDecryptionVerifier(address verifier) external view {
        if (verifier.code.length == 0)
            revert IInterfold.InvalidEncryptionScheme(bytes32(0));
        uint256 actual = IDecryptionVerifier(verifier).threshold();
        uint256 expected = ActiveCryptoConfig.t();
        if (actual != expected)
            revert IInterfold.VerifierThresholdMismatch(actual, expected);
    }

    /// @notice Checks the request input window and total duration.
    function validateRequest(
        uint256[2] calldata inputWindow,
        uint256 nowTs,
        address registryAddress,
        IInterfold.E3TimeoutConfig calldata timeoutConfig,
        uint256 maxDuration
    ) external view {
        if (inputWindow[0] < nowTs)
            revert IInterfold.InvalidInputDeadlineStart(inputWindow[0]);
        if (inputWindow[1] < inputWindow[0])
            revert IInterfold.InvalidInputDeadlineEnd(inputWindow[1]);
        uint256 totalDuration = requestLifecycleDuration(
            inputWindow[1],
            nowTs,
            registryAddress,
            timeoutConfig
        );
        if (totalDuration > maxDuration)
            revert IInterfold.InvalidDuration(totalDuration);
    }

    /// @notice Returns the worst-case request-to-decryption duration.
    function requestLifecycleDuration(
        uint256 inputWindowEnd,
        uint256 requestTime,
        address registryAddress,
        IInterfold.E3TimeoutConfig memory timeoutConfig
    ) public view returns (uint256 duration) {
        if (inputWindowEnd < requestTime)
            revert IInterfold.InvalidInputDeadlineEnd(inputWindowEnd);
        uint256 inputReservation = inputWindowEnd - requestTime;
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        uint256 committeeReservation = registry.randomnessRequestTimeout() +
            registry.sortitionSubmissionWindow() +
            timeoutConfig.dkgWindow;
        uint256 preCompute = inputReservation > committeeReservation
            ? inputReservation
            : committeeReservation;
        return
            preCompute +
            timeoutConfig.computeWindow +
            timeoutConfig.decryptionWindow;
    }

    /// @notice Cancels an E3 whose randomness request expired without a usable result.
    function cancelE3(
        mapping(uint256 => IInterfold.E3Stage) storage stages,
        mapping(uint256 => IInterfold.FailureReason) storage failureReasons,
        mapping(uint256 => address) storage requesters,
        address registryAddress,
        uint256 e3Id,
        address caller
    ) external {
        address requester = requesters[e3Id];
        if (requester == address(0)) revert IInterfold.E3DoesNotExist(e3Id);
        if (caller != requester) revert IInterfold.NotRequester(e3Id, caller);
        IInterfold.E3Stage stage = stages[e3Id];
        if (stage != IInterfold.E3Stage.Requested) {
            revert IInterfold.E3NotCancellable(e3Id, stage);
        }
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        (bool randomnessReady, ) = registry.sortitionSeed(e3Id);
        if (
            randomnessReady ||
            block.timestamp <= registry.getCommitteeDeadline(e3Id)
        ) revert IInterfold.E3NotCancellable(e3Id, stage);
        stages[e3Id] = IInterfold.E3Stage.Failed;
        failureReasons[e3Id] = IInterfold
            .FailureReason
            .CommitteeFormationTimeout;
        emit IInterfold.E3StageChanged(e3Id, stage, IInterfold.E3Stage.Failed);
        emit IInterfold.E3Failed(
            e3Id,
            stage,
            IInterfold.FailureReason.CommitteeFormationTimeout
        );
        registry.releaseCommittee(e3Id);
    }
}
