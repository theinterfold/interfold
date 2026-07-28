// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IInterfold } from "../interfaces/IInterfold.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { IDecryptionVerifier } from "../interfaces/IDecryptionVerifier.sol";

/**
 * @title InterfoldPricing
 * @notice External library extracted from {Interfold} to keep its deployed
 *         runtime bytecode under the EIP-170 24,576-byte cap.
 *
 *         All functions contain validation / fee-quote math. They are
 *         declared `external` so Solidity emits a linked library DELEGATECALL
 *         site at each call instead of inlining the bytes into Interfold.
 *
 *         Behaviour and revert selectors match the inlined originals: typed
 *         errors are imported from {IInterfold} so off-chain
 *         `revertedWithCustomError` lookups against the Interfold ABI continue
 *         to resolve.
 */
library InterfoldPricing {
    uint16 internal constant BPS_BASE = 10000;
    uint16 internal constant MAX_PROTOCOL_SHARE_BPS = 5_000;
    uint16 internal constant MAX_MARGIN_BPS = 5_000;
    uint32 internal constant MAX_COMMITTEE_SIZE = 256;

    event ParamSetRegistered(uint8 paramSet, bytes encodedParams);
    event ParamSetUpdated(
        uint8 paramSet,
        bytes previousParams,
        bytes newParams
    );

    function emitParamSetChange(
        uint8 paramSet,
        bytes calldata previous,
        bytes calldata current
    ) external {
        if (previous.length == 0) {
            emit ParamSetRegistered(paramSet, current);
        } else {
            emit ParamSetUpdated(paramSet, previous, current);
        }
    }

    function validateRegistryCaller(
        address caller,
        address registry
    ) external pure {
        require(caller == registry, IInterfold.OnlyCiphernodeRegistry());
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
        IDecryptionVerifier(verifierAddress).verify(
            e3Id,
            decryptionDomain,
            plaintextHash,
            committeeHash,
            ciphertextCommitment,
            proof
        );
    }

    function honestNodes(
        address registryAddress,
        uint256 e3Id,
        uint8 reason
    ) external view returns (address[] memory) {
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        if (
            reason ==
            uint8(IInterfold.FailureReason.CommitteeFormationTimeout) ||
            reason ==
            uint8(IInterfold.FailureReason.InsufficientCommitteeMembers)
        ) return new address[](0);

        try registry.getActiveCommitteeNodes(e3Id) returns (
            address[] memory nodes,
            uint256[] memory
        ) {
            return nodes;
        } catch {
            return new address[](0);
        }
    }

    /// @notice Mirrors the four validation gates at the top of
    ///         {Interfold.publishCiphertextOutput}.
    /// @param current  ABI-encoded as `uint8` to avoid qualified enum names in
    ///                 the library ABI (ethers v6 rejects `IInterfold.E3Stage`).
    function validatePublishCiphertext(
        uint256 e3Id,
        uint8 current,
        uint256 computeDeadline,
        uint256 inputWindowEnd,
        bytes32 ciphertextOutput,
        uint256 nowTs
    ) external pure {
        IInterfold.E3Stage stage = IInterfold.E3Stage(current);
        if (stage != IInterfold.E3Stage.KeyPublished)
            revert IInterfold.InvalidStage(
                e3Id,
                IInterfold.E3Stage.KeyPublished,
                stage
            );
        if (computeDeadline < nowTs)
            revert IInterfold.CommitteeDutiesCompleted(e3Id, computeDeadline);
        if (nowTs < inputWindowEnd)
            revert IInterfold.InputDeadlineNotReached(e3Id, inputWindowEnd);
        if (ciphertextOutput != bytes32(0))
            revert IInterfold.CiphertextOutputAlreadyPublished(e3Id);
    }

    /// @notice Mirrors the three stage-precondition reverts at the top of
    ///         {Interfold.markE3Failed} and {Interfold._markE3FailedWithReason}.
    /// @param current  ABI-encoded as `uint8` to avoid qualified enum names in
    ///                 the library ABI (ethers v6 rejects `IInterfold.E3Stage`).
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
            !ICiphernodeRegistry(registry).isCommitteeMember(e3Id, caller)
        ) revert IInterfold.MarkE3FailedInGracePeriod(e3Id, graceEnds);
    }

    /// @notice Mirrors the threshold / min-size gates at the top of
    ///         {Interfold.getE3Quote} (post param-set existence check).
    /// @param committeeSize  ABI-encoded as `uint8` to avoid qualified enum
    ///                       names in the library ABI (ethers v6 rejects
    ///                       `IInterfold.CommitteeSize`).
    function validateQuoteThresholds(
        uint32[2] memory threshold,
        uint8 committeeSize,
        uint32 minCommitteeSize,
        uint32 minThreshold
    ) external pure {
        IInterfold.CommitteeSize size = IInterfold.CommitteeSize(committeeSize);
        if (threshold[1] == 0)
            revert IInterfold.CommitteeSizeNotConfigured(size);
        if (minCommitteeSize > 0 && threshold[1] < minCommitteeSize)
            revert IInterfold.CommitteeSizeTooSmall(size);
        if (minThreshold > 0 && threshold[0] < minThreshold)
            revert IInterfold.ThresholdTooSmall(threshold[0]);
    }

    /// @notice Mirrors {Interfold._setTimeoutConfig} validation.
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

    /// @notice Mirrors {Interfold.setCommitteeThresholds} validation. The
    ///         caller still writes the mapping to preserve storage layout.
    function validateCommitteeThresholds(
        uint32[2] calldata threshold,
        uint32 minCommitteeSize,
        uint32 minThreshold
    ) external pure {
        if (threshold[0] == 0 || threshold[1] < threshold[0])
            revert IInterfold.InvalidThresholdValues();
        // Hard cap on configured committee size to bound on-chain loops
        // (sortition, reward distribution) against governance misconfiguration.
        if (threshold[1] > MAX_COMMITTEE_SIZE)
            revert IInterfold.InvalidThresholdValues();
        if (minCommitteeSize > 0 && threshold[1] < minCommitteeSize)
            revert IInterfold.BelowMinCommitteeSize(
                threshold[1],
                minCommitteeSize
            );
        if (minThreshold > 0 && threshold[0] < minThreshold)
            revert IInterfold.BelowMinThreshold(threshold[0], minThreshold);
    }

    /// @notice Mirrors the input-window and duration gates
    ///         of {Interfold.request}. Reverts with the same selectors so off-
    ///         chain `revertedWithCustomError(interfold, ...)` lookups keep
    ///         working.
    /// @param inputWindow      `requestParams.inputWindow` ([start, end]).
    /// @param nowTs            `block.timestamp` from the caller.
    /// @param computeWindow    `_timeoutConfig.computeWindow`.
    /// @param decryptionWindow `_timeoutConfig.decryptionWindow`.
    /// @param maxDuration      The Interfold-wide upper bound.
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
        if (totalDuration >= maxDuration)
            revert IInterfold.InvalidDuration(totalDuration);
    }

    /// @notice Mirrors {Interfold.setPricingConfig} validation.
    function validatePricingConfig(
        IInterfold.PricingConfig calldata config
    ) external pure {
        if (config.marginBps > MAX_MARGIN_BPS)
            revert IInterfold.BpsExceedsMax(config.marginBps);
        if (config.protocolShareBps > MAX_PROTOCOL_SHARE_BPS)
            revert IInterfold.BpsExceedsMax(config.protocolShareBps);
        if (config.dkgUtilizationBps > BPS_BASE)
            revert IInterfold.UtilizationBpsExceedsMax(
                config.dkgUtilizationBps
            );
        if (config.computeUtilizationBps > BPS_BASE)
            revert IInterfold.UtilizationBpsExceedsMax(
                config.computeUtilizationBps
            );
        if (config.decryptUtilizationBps > BPS_BASE)
            revert IInterfold.UtilizationBpsExceedsMax(
                config.decryptUtilizationBps
            );
        if (
            config.protocolShareBps != 0 &&
            config.protocolTreasury == address(0)
        ) revert IInterfold.TreasuryRequired();
        if (config.minCommitteeSize < config.minThreshold)
            revert IInterfold.MinSizeBelowMinThreshold();
    }

    /// @notice Splits `cnAmount` equally across `n` slots, sweeping any
    ///         integer-division dust into a slot chosen by `e3Id % n`.
    ///         Matches the original {Interfold._computeNodeAmounts}.
    function computeNodeAmounts(
        uint256 cnAmount,
        uint256 n,
        uint256 e3Id
    ) external pure returns (uint256[] memory amounts) {
        amounts = new uint256[](n);
        uint256 per = cnAmount / n;
        for (uint256 i = 0; i < n; i++) amounts[i] = per;
        uint256 dust = cnAmount - per * n;
        if (dust > 0) amounts[e3Id % n] += dust;
    }

    /// @notice Pure fee quote math. The caller (Interfold) is responsible for
    ///         loading the per-call inputs and gating on min-committee / min-
    ///         threshold (so we keep the original {CommitteeSize} discriminator
    ///         in revert data).
    /// @param pc                  Snapshot of `_pricingConfig`.
    /// @param tc                  Snapshot of `_timeoutConfig`.
    /// @param sortitionWindow     Result of `ciphernodeRegistry.sortitionSubmissionWindow()`.
    /// @param threshold           `[quorum, total]` resolved from `committeeThresholds`.
    /// @param inputWindowStart    `requestParams.inputWindow[0]`.
    /// @param inputWindowEnd      `requestParams.inputWindow[1]`.
    function quote(
        IInterfold.PricingConfig calldata pc,
        IInterfold.E3TimeoutConfig calldata tc,
        uint256 sortitionWindow,
        uint32[2] calldata threshold,
        uint256 inputWindowStart,
        uint256 inputWindowEnd
    ) external view returns (uint256 fee) {
        if (inputWindowEnd < inputWindowStart)
            revert IInterfold.InvalidInputDeadlineEnd(inputWindowEnd);

        {
            uint256 computeDeadline = inputWindowEnd + tc.computeWindow;
            uint256 committeeDeadline = block.timestamp + sortitionWindow;
            if (computeDeadline <= committeeDeadline)
                revert IInterfold.ComputeDeadlinePrecedesCommitteeFinalization(
                    computeDeadline,
                    committeeDeadline
                );
        }

        uint256 n = uint256(threshold[1]); // total committee size
        uint256 m = uint256(threshold[0]); // quorum/decryption threshold

        // Duration covers the full availability period, using expected-case
        // utilization fractions for protocol-controlled timeout windows.
        // Sum the BPS-weighted windows first then divide once so the
        // duration does not lose up to ~3 seconds of weight to per-term
        // integer-division truncation.
        uint256 weightedTimeoutsBps = tc.dkgWindow *
            uint256(pc.dkgUtilizationBps) +
            tc.computeWindow *
            uint256(pc.computeUtilizationBps) +
            tc.decryptionWindow *
            uint256(pc.decryptUtilizationBps);
        uint256 duration = sortitionWindow +
            inputWindowEnd -
            inputWindowStart +
            weightedTimeoutsBps /
            uint256(BPS_BASE);

        // ZK proof count per node: 14 fixed + 4 × (N-1) scaling.
        uint256 proofsPerNode = 14 + 4 * (n - 1);

        // Key generation cost: fixed per-node + per-proof (quadratic in n)
        uint256 baseFee = pc.keyGenFixedPerNode * n;
        baseFee += pc.keyGenPerEncryptionProof * n * proofsPerNode;

        // Key generation coordination cost (quadratic in n)
        if (n > 1) {
            baseFee += (pc.coordinationPerPair * (n * (n - 1))) / 2;
        }

        // Proof verification cost: each node verifies all others' proofs.
        baseFee += pc.verificationPerProof * n * proofsPerNode;

        // Availability cost (linear in n × duration)
        baseFee += pc.availabilityPerNodePerSec * n * duration;

        // Decryption cost (linear in m)
        baseFee += pc.decryptionPerNode * m;
        // Decryption coordination cost (quadratic in m)
        if (m > 1) {
            baseFee += (pc.coordinationPerPair * (m * (m - 1))) / 2;
        }

        // Publication base cost
        baseFee += pc.publicationBase;

        // Apply margin markup
        fee =
            (baseFee * (uint256(BPS_BASE) + uint256(pc.marginBps))) /
            uint256(BPS_BASE);

        if (fee == 0) revert IInterfold.PaymentRequired(fee);
    }
}
