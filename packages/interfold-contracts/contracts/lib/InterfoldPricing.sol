// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IInterfold } from "../interfaces/IInterfold.sol";
import { IE3RefundManager } from "../interfaces/IE3RefundManager.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ActiveCryptoConfig } from "./ActiveCryptoConfig.sol";

/**
 * @title InterfoldPricing
 * @notice External library extracted from {Interfold} to keep its deployed
 *         runtime bytecode under the EIP-170 24,576-byte cap.
 *
 *         Functions contain fee-quote math, pricing validation, and bounded
 *         reward accounting. External calls use DELEGATECALL to keep this code
 *         out of the Interfold runtime bytecode.
 */
library InterfoldPricing {
    using SafeERC20 for IERC20;
    uint16 internal constant BPS_BASE = 10000;
    event RewardCredited(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );
    event RewardClaimed(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );
    event TreasuryClaimed(
        address indexed treasury,
        IERC20 indexed token,
        uint256 amount
    );

    /// @notice Updates only the non-refundable randomness fee.
    function setRandomnessFlatFee(
        IInterfold.PricingConfig storage config,
        IERC20 token,
        uint8 tokenDecimals,
        uint192 randomnessFlatFee
    ) external {
        if (randomnessFlatFee == 0) revert IInterfold.PaymentRequired(0);
        config.randomnessFlatFee = randomnessFlatFee;
        emit IInterfold.FeeAssetConfigUpdated(token, tokenDecimals, config);
    }

    /// @notice Pull an exact token amount into a custody contract.
    function transferFromExact(
        IERC20 token,
        address sender,
        address recipient,
        uint256 amount
    ) external {
        uint256 balanceBefore = token.balanceOf(recipient);
        token.safeTransferFrom(sender, recipient, amount);
        _requireExactReceipt(token, recipient, balanceBefore, amount);
    }

    /// @notice Drain one E3 reward and transfer it to its recipient.
    function claimReward(
        mapping(uint256 => mapping(address => uint256)) storage pendingRewards,
        mapping(uint256 => IERC20) storage feeTokens,
        uint256 e3Id,
        address account
    ) external returns (uint256 amount) {
        amount = pendingRewards[e3Id][account];
        if (amount == 0) return 0;
        pendingRewards[e3Id][account] = 0;
        IERC20 token = feeTokens[e3Id];
        _transferExact(token, account, amount);
        emit RewardClaimed(e3Id, account, token, amount);
    }

    /// @notice Drain one treasury balance and transfer it to the treasury.
    function claimTreasury(
        mapping(address => mapping(IERC20 => uint256)) storage pendingTreasury,
        address treasury,
        IERC20 token
    ) external returns (uint256 amount) {
        amount = pendingTreasury[treasury][token];
        if (amount == 0) return 0;
        pendingTreasury[treasury][token] = 0;
        _transferExact(token, treasury, amount);
        emit TreasuryClaimed(treasury, token, amount);
    }

    /// @notice Records service escrow and credits the randomness fee.
    function recordRequestPayment(
        mapping(uint256 e3Id => uint256 amount) storage e3Payments,
        mapping(uint256 e3Id => IERC20 token) storage feeTokens,
        mapping(uint256 e3Id => uint16 bps) storage protocolShareBps,
        mapping(uint256 e3Id => address treasury) storage protocolTreasuries,
        mapping(address treasury => mapping(IERC20 token => uint256 amount))
            storage pendingTreasury,
        IInterfold.PricingConfig storage pricing,
        uint256 e3Id,
        uint256 quotedFee,
        IERC20 token
    ) external {
        uint256 randomnessFee = pricing.randomnessFlatFee;
        address treasury = pricing.protocolTreasury;
        e3Payments[e3Id] = quotedFee - randomnessFee;
        feeTokens[e3Id] = token;
        protocolShareBps[e3Id] = pricing.protocolShareBps;
        protocolTreasuries[e3Id] = treasury;
        pendingTreasury[treasury][token] += randomnessFee;
        emit IInterfold.TreasuryCredited(e3Id, treasury, token, randomnessFee);
    }

    /// @notice Transfers service escrow and calculates one failed-E3 refund.
    function processE3Failure(
        mapping(uint256 e3Id => uint256 amount) storage e3Payments,
        mapping(uint256 e3Id => IERC20 token) storage feeTokens,
        uint8 stage,
        address registry,
        IE3RefundManager refundManager,
        uint256 e3Id
    ) external {
        if (stage != uint8(IInterfold.E3Stage.Failed))
            revert IInterfold.E3NotFailed(e3Id);

        uint256 payment = e3Payments[e3Id];
        if (payment == 0) revert IInterfold.NoPaymentToRefund(e3Id);
        e3Payments[e3Id] = 0;

        (address[] memory honestNodes, ) = ICiphernodeRegistry(registry)
            .getActiveCommitteeNodes(e3Id);
        IERC20 paymentToken = feeTokens[e3Id];
        _transferExact(paymentToken, address(refundManager), payment);
        refundManager.calculateRefund(e3Id, payment, honestNodes, paymentToken);
        emit IInterfold.E3FailureProcessed(e3Id, payment, honestNodes.length);
    }

    /// @notice Validates a fee asset and every raw-unit price tied to it.
    function validateFeeAssetConfig(
        IInterfold.FeeAssetConfig calldata config,
        uint16 maxMarginBps,
        uint16 maxProtocolShareBps
    ) external view {
        IERC20 token = IERC20(config.token);
        if (address(token).code.length == 0) {
            revert IInterfold.InvalidFeeToken(token);
        }
        (bool success, bytes memory result) = address(token).staticcall(
            abi.encodeWithSignature("decimals()")
        );
        if (!success || result.length != 32) {
            revert IInterfold.FeeTokenDecimalsUnavailable(token);
        }
        uint256 decoded = abi.decode(result, (uint256));
        if (decoded > type(uint8).max) {
            revert IInterfold.FeeTokenDecimalsUnavailable(token);
        }
        uint8 actualDecimals = uint8(decoded);
        if (actualDecimals != config.expectedDecimals) {
            revert IInterfold.FeeTokenDecimalsMismatch(
                token,
                config.expectedDecimals,
                actualDecimals
            );
        }

        if (config.pricing.randomnessFlatFee == 0)
            revert IInterfold.PaymentRequired(config.pricing.randomnessFlatFee);

        _validatePricingConfig(
            config.pricing,
            maxMarginBps,
            maxProtocolShareBps
        );
    }

    function _validatePricingConfig(
        IInterfold.PricingConfig calldata config,
        uint16 maxMarginBps,
        uint16 maxProtocolShareBps
    ) private pure {
        if (config.marginBps > maxMarginBps)
            revert IInterfold.BpsExceedsMax(config.marginBps);
        if (config.protocolShareBps > maxProtocolShareBps)
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
        if (config.protocolTreasury == address(0))
            revert IInterfold.TreasuryRequired();
        if (config.minCommitteeSize < config.minThreshold)
            revert IInterfold.MinSizeBelowMinThreshold();
    }

    /// @notice Splits and credits committee rewards to each frozen recipient.
    /// @dev Integer-division dust goes to the slot selected by `e3Id % n`.
    /// @dev Runs through a linked library call to keep the accounting loop out
    ///      of Interfold's size-constrained runtime bytecode.
    function _computeAndCreditRewards(
        mapping(uint256 => mapping(address => uint256)) storage pendingRewards,
        IE3RefundManager refundManager,
        uint256 cnAmount,
        uint256 e3Id,
        address[] memory nodes,
        IERC20 token
    ) private returns (uint256[] memory amounts) {
        uint256 n = nodes.length;
        amounts = new uint256[](n);
        uint256 per = cnAmount / n;
        uint256 dust = cnAmount - per * n;
        uint256 dustIndex = e3Id % n;
        for (uint256 i = 0; i < n; i++) {
            uint256 amount = per;
            if (i == dustIndex) amount += dust;
            amounts[i] = amount;
            if (amount > 0) {
                _creditReward(
                    pendingRewards,
                    refundManager,
                    e3Id,
                    nodes[i],
                    token,
                    amount
                );
            }
        }
    }

    /// @notice Settles one successful E3 into pull-payment ledgers.
    function distributeRewards(
        mapping(uint256 e3Id => uint256 amount) storage e3Payments,
        mapping(uint256 e3Id => IERC20 token) storage feeTokens,
        mapping(uint256 e3Id => address requester) storage requesters,
        mapping(uint256 e3Id => uint16 bps) storage protocolShareBps,
        mapping(uint256 e3Id => address treasury) storage protocolTreasuries,
        mapping(address treasury => mapping(IERC20 token => uint256 amount))
            storage pendingTreasury,
        mapping(uint256 e3Id => mapping(address account => uint256 amount))
            storage pendingRewards,
        address registryAddress,
        IE3RefundManager refundManager,
        uint256 e3Id
    ) external {
        (address[] memory activeNodes, ) = ICiphernodeRegistry(registryAddress)
            .getActiveCommitteeNodes(e3Id);
        uint256 totalAmount = e3Payments[e3Id];
        e3Payments[e3Id] = 0;
        IERC20 paymentToken = feeTokens[e3Id];

        if (totalAmount == 0) {
            refundManager.distributeSlashedFundsOnSuccess(e3Id, paymentToken);
            return;
        }

        uint256 activeLength = activeNodes.length;
        if (activeLength == 0) {
            address requester = requesters[e3Id];
            if (requester == address(0)) revert IInterfold.E3DoesNotExist(e3Id);
            _transferExact(paymentToken, requester, totalAmount);
            refundManager.distributeSlashedFundsOnSuccess(e3Id, paymentToken);
            return;
        }

        uint256 protocolAmount;
        uint16 shareBps = protocolShareBps[e3Id];
        address treasury = protocolTreasuries[e3Id];
        if (shareBps > 0 && treasury != address(0)) {
            protocolAmount =
                (totalAmount * uint256(shareBps)) /
                uint256(BPS_BASE);
            if (protocolAmount > 0) {
                pendingTreasury[treasury][paymentToken] += protocolAmount;
                emit IInterfold.TreasuryCredited(
                    e3Id,
                    treasury,
                    paymentToken,
                    protocolAmount
                );
            }
        }

        uint256[] memory amounts = _computeAndCreditRewards(
            pendingRewards,
            refundManager,
            totalAmount - protocolAmount,
            e3Id,
            activeNodes,
            paymentToken
        );
        emit IInterfold.RewardsDistributed(e3Id, activeNodes, amounts);
        refundManager.distributeSlashedFundsOnSuccess(e3Id, paymentToken);
    }

    function _creditReward(
        mapping(uint256 => mapping(address => uint256)) storage pendingRewards,
        IE3RefundManager refundManager,
        uint256 e3Id,
        address operator,
        IERC20 token,
        uint256 amount
    ) private {
        (address recipient, bool held) = refundManager.rewardDisposition(
            e3Id,
            operator
        );
        if (held) {
            _transferExact(token, address(refundManager), amount);
            refundManager.holdSuccessReward(e3Id, operator, token, amount);
        } else {
            pendingRewards[e3Id][recipient] += amount;
            emit RewardCredited(e3Id, recipient, token, amount);
        }
    }

    function _transferExact(
        IERC20 token,
        address recipient,
        uint256 amount
    ) private {
        uint256 custodyBefore = token.balanceOf(address(this));
        uint256 recipientBefore = token.balanceOf(recipient);
        token.safeTransfer(recipient, amount);
        _requireExactReceipt(token, recipient, recipientBefore, amount);
        uint256 custodyAfter = token.balanceOf(address(this));
        uint256 spent = custodyBefore > custodyAfter
            ? custodyBefore - custodyAfter
            : 0;
        if (spent != amount) {
            revert IInterfold.AssetTransferMismatch(token, amount, spent);
        }
    }

    function _requireExactReceipt(
        IERC20 token,
        address recipient,
        uint256 balanceBefore,
        uint256 expected
    ) private view {
        uint256 balanceAfter = token.balanceOf(recipient);
        uint256 actual = balanceAfter > balanceBefore
            ? balanceAfter - balanceBefore
            : 0;
        if (actual != expected) {
            revert IInterfold.AssetTransferMismatch(token, expected, actual);
        }
    }

    /// @notice Pure fee quote math. The caller (Interfold) is responsible for
    ///         loading the per-call inputs and gating on min-committee / min-
    ///         threshold (so we keep the original {CommitteeSize} discriminator
    ///         in revert data).
    /// @param pc                  Snapshot of `_pricingConfig`.
    /// @param tc                  Snapshot of `_timeoutConfig`.
    /// @param sortitionWindow     Result of `ciphernodeRegistry.sortitionSubmissionWindow()`.
    /// @param paramSet            BFV parameter-set enum value.
    /// @param committeeSize       Committee-size enum value.
    /// @param threshold           `[H, N]` resolved from `committeeThresholds`.
    /// @param requestTime         Timestamp used for request validation and pricing.
    /// @param inputWindowStart    `requestParams.inputWindow[0]`.
    /// @param inputWindowEnd      `requestParams.inputWindow[1]`.
    function quote(
        IInterfold.PricingConfig calldata pc,
        IInterfold.E3TimeoutConfig calldata tc,
        uint256 sortitionWindow,
        uint8 paramSet,
        uint8 committeeSize,
        uint32[2] calldata threshold,
        uint256 requestTime,
        uint256 inputWindowStart,
        uint256 inputWindowEnd
    ) external view returns (uint256 fee) {
        _validateQuoteWindow(requestTime, inputWindowStart, inputWindowEnd);

        if (!ActiveCryptoConfig.isParamSetSupported(paramSet))
            revert IInterfold.UnsupportedCryptoConfig();
        IInterfold.CommitteeSize size = IInterfold.CommitteeSize(committeeSize);
        if (threshold[1] == 0)
            revert IInterfold.CommitteeSizeNotConfigured(size);
        if (pc.minCommitteeSize > 0 && threshold[1] < pc.minCommitteeSize)
            revert IInterfold.CommitteeSizeTooSmall(size);
        if (pc.minThreshold > 0 && threshold[0] < pc.minThreshold)
            revert IInterfold.ThresholdTooSmall(threshold[0]);

        ActiveCryptoConfig.validateCommittee(committeeSize, threshold);
        uint256 n = uint256(threshold[1]);
        uint256 h = uint256(threshold[0]);

        uint256 duration = _billableDuration(
            pc,
            tc,
            sortitionWindow,
            requestTime,
            inputWindowStart,
            inputWindowEnd
        );

        uint256 baseFee = _baseFee(pc, n, h, duration);

        // Apply the margin only to ciphernode services. The flat randomness
        // fee reimburses the protocol-funded subscription without a markup.
        fee =
            (baseFee * (uint256(BPS_BASE) + uint256(pc.marginBps))) /
            uint256(BPS_BASE);

        if (fee == 0) revert IInterfold.PaymentRequired(fee);
        if (pc.randomnessFlatFee == 0)
            revert IInterfold.PaymentRequired(pc.randomnessFlatFee);
        fee += pc.randomnessFlatFee;
    }

    function _validateQuoteWindow(
        uint256 requestTime,
        uint256 inputWindowStart,
        uint256 inputWindowEnd
    ) private pure {
        if (inputWindowStart < requestTime)
            revert IInterfold.InvalidInputDeadlineStart(inputWindowStart);
        if (inputWindowEnd < inputWindowStart)
            revert IInterfold.InvalidInputDeadlineEnd(inputWindowEnd);
    }

    function _baseFee(
        IInterfold.PricingConfig calldata pc,
        uint256 n,
        uint256 h,
        uint256 duration
    ) private pure returns (uint256 baseFee) {
        // ZK proof count per node: 14 fixed + 4 × (N-1) scaling.
        uint256 proofsPerNode = 14 + 4 * (n - 1);

        // Key generation cost: fixed per-node + per-proof (quadratic in n)
        baseFee = pc.keyGenFixedPerNode * n;
        baseFee += pc.keyGenPerEncryptionProof * n * proofsPerNode;

        // Key generation coordination cost (quadratic in n)
        if (n > 1) {
            baseFee += (pc.coordinationPerPair * (n * (n - 1))) / 2;
        }

        // Proof verification cost: each node verifies all others' proofs.
        baseFee += pc.verificationPerProof * n * proofsPerNode;

        // Availability cost (linear in n × duration)
        baseFee += pc.availabilityPerNodePerSec * n * duration;

        // Decryption cost (linear in the required H shares)
        baseFee += pc.decryptionPerNode * h;
        // Decryption coordination cost (quadratic in H)
        if (h > 1) {
            baseFee += (pc.coordinationPerPair * (h * (h - 1))) / 2;
        }

        // Publication base cost
        baseFee += pc.publicationBase;
    }

    function _billableDuration(
        IInterfold.PricingConfig calldata pc,
        IInterfold.E3TimeoutConfig calldata tc,
        uint256 sortitionWindow,
        uint256 requestTime,
        uint256 inputWindowStart,
        uint256 inputWindowEnd
    ) private pure returns (uint256) {
        // Charge at least the complete request-to-input-end reservation. For
        // near-term requests, preserve the existing weighted DKG estimate.
        uint256 inputWindowLength = inputWindowEnd - inputWindowStart;
        uint256 weightedPreComputeBps = (sortitionWindow + inputWindowLength) *
            BPS_BASE +
            tc.dkgWindow *
            uint256(pc.dkgUtilizationBps);
        uint256 reservedThroughInputEndBps = (inputWindowEnd - requestTime) *
            BPS_BASE;
        uint256 preComputeBps = weightedPreComputeBps >
            reservedThroughInputEndBps
            ? weightedPreComputeBps
            : reservedThroughInputEndBps;

        // Sum all weighted terms before division to avoid per-term rounding.
        uint256 durationBps = preComputeBps +
            tc.computeWindow *
            uint256(pc.computeUtilizationBps) +
            tc.decryptionWindow *
            uint256(pc.decryptUtilizationBps);
        return durationBps / uint256(BPS_BASE);
    }
}
