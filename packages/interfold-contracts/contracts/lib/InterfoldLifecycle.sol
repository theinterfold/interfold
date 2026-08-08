// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IInterfold } from "../interfaces/IInterfold.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IE3RefundManager } from "../interfaces/IE3RefundManager.sol";
import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";
import { IPkVerifier } from "../interfaces/IPkVerifier.sol";
import { ICiphertextVerifier } from "../interfaces/ICiphertextVerifier.sol";
import { E3 } from "../interfaces/IE3.sol";
import {
    CiphertextVerifierStorage
} from "../storage/CiphertextVerifierStorage.sol";
import { ActiveCryptoConfig } from "./ActiveCryptoConfig.sol";

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
    // ERC-7201 slot for "interfold.storage.CiphertextPublication".
    // keccak256(abi.encode(uint256(keccak256(namespace)) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant CIPHERTEXT_PUBLICATION_STORAGE_SLOT =
        0x8cf8f319e286c91067df5865ff01615e7f3fced906e24ea85acdc2dfd6704200;

    struct CiphertextPublicationLayout {
        mapping(uint256 e3Id => bool inProgress) inProgress;
    }

    /// @notice Validates finalization and freezes committee reward recipients.
    function validateAndSnapshotCommitteeFinalization(
        address caller,
        address registryAddress,
        address refundManagerAddress,
        uint256 e3Id,
        uint8 current
    ) external {
        if (caller != registryAddress)
            revert IInterfold.OnlyCiphernodeRegistry();
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage != IInterfold.E3Stage.Requested)
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.Requested,
                stage
            );
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

    function honestNodes(
        address registryAddress,
        uint256 e3Id
    ) external view returns (address[] memory) {
        (address[] memory nodes, ) = ICiphernodeRegistry(registryAddress)
            .getActiveCommitteeNodes(e3Id);
        return nodes;
    }

    /// @notice Validates, verifies, and records one ciphertext output.
    function publishCiphertext(
        mapping(uint256 e3Id => E3 e3) storage e3s,
        mapping(uint256 e3Id => IInterfold.E3Stage stage) storage stages,
        mapping(uint256 e3Id => IInterfold.E3Deadlines deadlines)
            storage deadlines,
        address registryAddress,
        uint256 e3Id,
        uint256 decryptionWindow,
        bytes calldata ciphertextOutput,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external returns (bool) {
        E3 storage e3 = e3s[e3Id];
        if (address(e3.e3Program) == address(0))
            revert IInterfold.E3DoesNotExist(e3Id);
        IInterfold.E3Stage stage = stages[e3Id];
        if (stage != IInterfold.E3Stage.KeyPublished)
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.KeyPublished,
                stage
            );
        uint256 computeDeadline = deadlines[e3Id].computeDeadline;
        if (computeDeadline < block.timestamp)
            revert IInterfold.CommitteeDutiesCompleted(e3Id, computeDeadline);
        if (block.timestamp < e3.inputWindow[1])
            revert IInterfold.InputDeadlineNotReached(e3Id, e3.inputWindow[1]);
        if (e3.ciphertextOutput != bytes32(0))
            revert IInterfold.CiphertextOutputAlreadyPublished(e3Id);
        _beginCiphertextPublication(e3Id);
        _requireViableCommittee(registryAddress, e3Id);

        bytes32 ciphertextOutputHash = keccak256(ciphertextOutput);
        _verifyCiphertext(
            e3,
            e3Id,
            ciphertextOutputHash,
            ciphertextCommitment,
            ciphertextOutput,
            proof
        );

        _endCiphertextPublication(e3Id);
        e3.ciphertextOutput = ciphertextOutputHash;
        e3.ciphertextCommitment = ciphertextCommitment;
        stages[e3Id] = IInterfold.E3Stage.CiphertextReady;
        deadlines[e3Id].decryptionDeadline = block.timestamp + decryptionWindow;

        emit IInterfold.CiphertextOutputPublished(
            e3Id,
            ciphertextOutput,
            ciphertextCommitment
        );
        emit IInterfold.E3StageChanged(
            e3Id,
            IInterfold.E3Stage.KeyPublished,
            IInterfold.E3Stage.CiphertextReady
        );
        return true;
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
    function snapshotCiphertextVerifier(
        uint256 e3Id,
        bytes32 encryptionSchemeId,
        bytes32 paramsHash
    ) external {
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

    function _verifyCiphertext(
        E3 storage e3,
        uint256 e3Id,
        bytes32 ciphertextOutputHash,
        bytes32 ciphertextCommitment,
        bytes calldata ciphertextOutput,
        bytes calldata proof
    ) private {
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
        ) revert IInterfold.InvalidOutput(ciphertextOutput);
        if (
            !e3.e3Program.verify(
                e3Id,
                ciphertextOutputHash,
                ciphertextCommitment,
                proof
            )
        ) revert IInterfold.InvalidOutput(ciphertextOutput);
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

    function _ciphertextPublicationLayout()
        private
        pure
        returns (CiphertextPublicationLayout storage state)
    {
        bytes32 slot = CIPHERTEXT_PUBLICATION_STORAGE_SLOT;
        assembly {
            state.slot := slot
        }
    }

    function _beginCiphertextPublication(uint256 e3Id) private {
        CiphertextPublicationLayout
            storage publication = _ciphertextPublicationLayout();
        require(
            !publication.inProgress[e3Id],
            "Ciphertext publication is already in progress"
        );
        publication.inProgress[e3Id] = true;
    }

    function _endCiphertextPublication(uint256 e3Id) private {
        _ciphertextPublicationLayout().inProgress[e3Id] = false;
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
    function stageDeadlineAndReason(
        address registryAddress, uint256 e3Id, uint8 current, IInterfold.E3Deadlines calldata deadlines
    ) external view returns (uint256 deadline, uint8 reason) {
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage == IInterfold.E3Stage.Requested)
            return (
                ICiphernodeRegistry(registryAddress).getCommitteeDeadline(e3Id),
                uint8(IInterfold.FailureReason.CommitteeFormationTimeout)
            );
        if (stage == IInterfold.E3Stage.CommitteeFinalized)
            return (
                deadlines.dkgDeadline,
                uint8(IInterfold.FailureReason.DKGTimeout)
            );
        if (stage == IInterfold.E3Stage.KeyPublished)
            return (
                deadlines.computeDeadline,
                uint8(IInterfold.FailureReason.ComputeTimeout)
            );
        if (stage == IInterfold.E3Stage.CiphertextReady)
            return (
                deadlines.decryptionDeadline,
                uint8(IInterfold.FailureReason.DecryptionTimeout)
            );
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
    ) external pure {
        if (alreadyRegistered)
            revert IInterfold.ParamSetAlreadyRegistered(paramSet);
        ActiveCryptoConfig.validateParamSet(paramSet, paramSetHash);
    }

    /// @notice Checks that a PK verifier matches the active DKG circuit.
    function validatePkVerifier(address verifier) external view {
        if (verifier.code.length == 0)
            revert IInterfold.InvalidEncryptionScheme(bytes32(0));
        uint256 actual = IPkVerifier(verifier).h();
        if (actual != ActiveCryptoConfig.H)
            revert IInterfold.VerifierThresholdMismatch(
                actual,
                ActiveCryptoConfig.H
            );
    }

    /// @notice Checks that a decryption verifier matches the active circuit.
    function validateDecryptionVerifier(address verifier) external view {
        if (verifier.code.length == 0)
            revert IInterfold.InvalidEncryptionScheme(bytes32(0));
        uint256 actual = IDecryptionVerifier(verifier).threshold();
        if (actual != ActiveCryptoConfig.T)
            revert IInterfold.VerifierThresholdMismatch(
                actual,
                ActiveCryptoConfig.T
            );
    }

    /// @notice Checks the request input window and total duration.
    function validateRequest(
        uint256[2] calldata inputWindow,
        uint256 nowTs,
        uint256 computeWindow,
        uint256 decryptionWindow,
        uint256 maxDuration
    ) external pure {
        if (inputWindow[0] < nowTs)
            revert IInterfold.InvalidInputDeadlineStart(inputWindow[0]);
        if (inputWindow[1] < inputWindow[0])
            revert IInterfold.InvalidInputDeadlineEnd(inputWindow[1]);
        uint256 totalDuration = inputWindow[1] -
            nowTs +
            computeWindow +
            decryptionWindow;
        if (totalDuration > maxDuration)
            revert IInterfold.InvalidDuration(totalDuration);
    }
}
