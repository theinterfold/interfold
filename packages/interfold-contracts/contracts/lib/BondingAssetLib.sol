// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IBondingRegistry } from "../interfaces/IBondingRegistry.sol";
import {
    ILockAwareCiphernodeBondToken
} from "../interfaces/ILockAwareCiphernodeBondToken.sol";
import {
    BONDING_SLASHING_STORAGE_SLOT,
    BondingSlashingStorage,
    SlashingManagerObligations
} from "../storage/BondingSlashingStorage.sol";
import { InterfoldTicketToken } from "../token/InterfoldTicketToken.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";
import { ExitQueueLib } from "./ExitQueueLib.sol";

/// @notice Keeps bonding-asset checks outside the size-constrained registry.
library BondingAssetLib {
    using SafeERC20 for IERC20;
    using ExitQueueLib for ExitQueueLib.ExitQueueState;

    function setRewardDistributor(
        mapping(address distributor => bool authorized) storage distributors,
        uint256 distributorCount,
        uint256 maximumDistributors,
        address distributor,
        bool authorized
    ) external returns (uint256 newDistributorCount) {
        if (authorized && distributor == address(0)) {
            revert IBondingRegistry.ZeroAddress();
        }
        bool wasAuthorized = distributors[distributor];
        newDistributorCount = distributorCount;
        if (wasAuthorized != authorized) {
            if (authorized) {
                if (distributorCount >= maximumDistributors) {
                    revert IBondingRegistry.MaxAuthorizedDistributors();
                }
                newDistributorCount = distributorCount + 1;
            } else {
                newDistributorCount = distributorCount - 1;
            }
        }
        distributors[distributor] = authorized;
        emit IBondingRegistry.RewardDistributorUpdated(distributor, authorized);
    }

    function distributeRewards(
        IERC20 rewardToken,
        mapping(address operator => address bondOwner) storage bondOwners,
        address distributor,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        if (recipients.length != amounts.length) {
            revert IBondingRegistry.ArrayLengthMismatch();
        }
        uint256 len = recipients.length;
        for (uint256 i = 0; i < len; ) {
            uint256 amount = amounts[i];
            if (amount != 0) {
                address recipient = bondOwners[recipients[i]];
                if (recipient == address(0)) recipient = recipients[i];
                rewardToken.safeTransferFrom(distributor, recipient, amount);
            }
            unchecked {
                ++i;
            }
        }
    }

    function claimExits(
        ExitQueueLib.ExitQueueState storage exits,
        InterfoldTicketToken ticketToken,
        IERC20 ciphernodeBondToken,
        mapping(address operator => address bondOwner) storage bondOwners,
        mapping(address bondOwner => uint256 amount) storage bondedByOwner,
        address operator,
        uint256 maxTicketAmount,
        uint256 maxCiphernodeBondAmount
    ) external returns (uint256 ciphernodeBondClaim) {
        (uint256 ticketClaim, uint256 claimedCiphernodeBond) = exits
            .claimAssets(operator, maxTicketAmount, maxCiphernodeBondAmount);
        if (ticketClaim == 0 && claimedCiphernodeBond == 0) {
            revert IBondingRegistry.ExitNotReady();
        }

        address bondOwner = bondOwners[operator];
        if (bondOwner == address(0)) revert IBondingRegistry.ZeroAddress();
        if (ticketClaim != 0) ticketToken.payout(bondOwner, ticketClaim);
        if (claimedCiphernodeBond != 0) {
            bondedByOwner[bondOwner] -= claimedCiphernodeBond;
            _transferExact(
                address(ciphernodeBondToken),
                bondOwner,
                claimedCiphernodeBond
            );
        }
        return claimedCiphernodeBond;
    }

    function validateExitTiming(
        address registryAddress,
        uint64 exitDelay
    ) external view {
        if (registryAddress == address(0) || exitDelay == 0) return;
        ICiphernodeRegistry registry = ICiphernodeRegistry(registryAddress);
        uint256 requiredDelay = registry.exitDelayFloor();
        if (exitDelay <= requiredDelay) {
            revert IBondingRegistry.ExitDelayMustExceedSortitionWindow(
                exitDelay,
                requiredDelay
            );
        }
    }

    function validateRegistryUpdate(
        address currentRegistryAddress,
        address newRegistryAddress,
        uint64 exitDelay,
        uint256 registeredOperators,
        uint256 activeOperators,
        uint256 unresolvedCommittees
    ) external view {
        if (newRegistryAddress == address(0)) {
            revert IBondingRegistry.ZeroAddress();
        }
        ICiphernodeRegistry newRegistry = ICiphernodeRegistry(
            newRegistryAddress
        );
        uint256 requiredDelay = newRegistry.exitDelayFloor();
        if (exitDelay != 0 && exitDelay <= requiredDelay) {
            revert IBondingRegistry.ExitDelayMustExceedSortitionWindow(
                exitDelay,
                requiredDelay
            );
        }
        if (
            currentRegistryAddress == address(0) ||
            currentRegistryAddress == newRegistryAddress
        ) return;
        if (
            registeredOperators != 0 ||
            activeOperators != 0 ||
            unresolvedCommittees != 0 ||
            newRegistry.numCiphernodes() != 0
        ) revert IBondingRegistry.InvalidConfiguration();
    }

    function availableTickets(
        address ticketTokenAddress,
        address operator,
        uint256 ticketPrice
    ) external view returns (uint256) {
        return
            InterfoldTicketToken(ticketTokenAddress).balanceOf(operator) /
            ticketPrice;
    }

    function ticketBalance(
        address ticketTokenAddress,
        address operator
    ) external view returns (uint256) {
        return InterfoldTicketToken(ticketTokenAddress).balanceOf(operator);
    }

    function ticketBalanceAt(
        address ticketTokenAddress,
        address operator,
        uint256 timepoint
    ) external view returns (uint256) {
        return
            InterfoldTicketToken(ticketTokenAddress).getPastVotes(
                operator,
                timepoint
            );
    }

    function validateBondingAssetConfig(
        address currentTicket,
        address currentCiphernodeBond,
        uint8 currentTicketDecimals,
        uint8 currentCiphernodeBondDecimals,
        uint64 configurationVersion,
        address registry,
        IBondingRegistry.BondingAssetConfig calldata config,
        address[] storage managers,
        mapping(address => uint256) storage pendingRoutes
    ) external returns (bool assetChanged) {
        if (config.ticketPrice == 0 || config.requiredCiphernodeBond == 0) {
            revert IBondingRegistry.InvalidConfiguration();
        }
        _validateTicketAsset(
            currentTicket,
            currentTicketDecimals,
            config.ticketToken,
            config.expectedTicketDecimals,
            registry
        );
        _validateCiphernodeBondAsset(
            currentCiphernodeBond,
            currentCiphernodeBondDecimals,
            config.ciphernodeBondToken,
            config.expectedCiphernodeBondDecimals,
            registry
        );

        assetChanged =
            currentTicket != config.ticketToken ||
            currentCiphernodeBond != config.ciphernodeBondToken ||
            currentTicketDecimals != config.expectedTicketDecimals ||
            currentCiphernodeBondDecimals !=
            config.expectedCiphernodeBondDecimals;
        if (assetChanged) {
            _requireNoAssetConfigurationObligations(managers, pendingRoutes);
        }
        emit IBondingRegistry.BondingAssetConfigUpdated(
            InterfoldTicketToken(config.ticketToken),
            IERC20(config.ciphernodeBondToken),
            config.ticketPrice,
            config.requiredCiphernodeBond,
            config.expectedTicketDecimals,
            config.expectedCiphernodeBondDecimals,
            configurationVersion + (assetChanged ? 1 : 0)
        );
    }

    function _validateTicketAsset(
        address current,
        uint8 currentDecimals,
        address next,
        uint8 expectedDecimals,
        address registry
    ) private view {
        if (next.code.length == 0) {
            revert IBondingRegistry.InvalidBondingAsset(next);
        }
        _validateDecimals(next, expectedDecimals);
        address configuredRegistry = _ticketRegistry(next);
        if (configuredRegistry != registry && current != address(0)) {
            revert IBondingRegistry.TicketTokenRegistryMismatch(
                configuredRegistry,
                registry
            );
        }
        if (
            current == address(0) ||
            (current == next && currentDecimals == expectedDecimals)
        ) return;

        InterfoldTicketToken token = InterfoldTicketToken(current);
        uint256 liabilities = token.totalSupply() + token.payableBalance();
        if (liabilities != 0) {
            revert IBondingRegistry.OutstandingAssetLiabilities(
                current,
                liabilities
            );
        }
    }

    function _ticketRegistry(address token) private view returns (address) {
        (bool success, bytes memory result) = token.staticcall(
            abi.encodeWithSignature("registry()")
        );
        if (!success || result.length != 32) {
            revert IBondingRegistry.InvalidBondingAsset(token);
        }
        return abi.decode(result, (address));
    }

    function _validateCiphernodeBondAsset(
        address current,
        uint8 currentDecimals,
        address next,
        uint8 expectedDecimals,
        address registry
    ) private view {
        if (next == address(0)) {
            if (current != address(0) || expectedDecimals != 0) {
                revert IBondingRegistry.InvalidBondingAsset(next);
            }
            return;
        }
        if (next.code.length == 0) {
            revert IBondingRegistry.InvalidBondingAsset(next);
        }
        _validateDecimals(next, expectedDecimals);
        if (
            current != address(0) &&
            (current != next || currentDecimals != expectedDecimals)
        ) {
            uint256 liabilities = IERC20(current).balanceOf(registry);
            if (liabilities != 0) {
                revert IBondingRegistry.OutstandingAssetLiabilities(
                    current,
                    liabilities
                );
            }
        }
        lockedBalanceOf(next, registry);
    }

    function _requireNoAssetConfigurationObligations(
        address[] storage managers,
        mapping(address => uint256) storage pendingRoutes
    ) private view {
        BondingSlashingStorage.Layout storage state = _slashingLayout();
        for (uint256 i = 0; i < managers.length; i++) {
            address manager = managers[i];
            SlashingManagerObligations storage obligations = state.managers[
                manager
            ];
            uint256 routes = pendingRoutes[manager];
            if (
                obligations.e3Assignments != 0 ||
                obligations.openSlashLocks != 0 ||
                routes != 0
            ) {
                revert IBondingRegistry.AssetConfigurationInUse(
                    manager,
                    obligations.e3Assignments,
                    obligations.openSlashLocks,
                    routes
                );
            }
        }
    }

    function _validateDecimals(
        address token,
        uint8 expectedDecimals
    ) private view {
        (bool success, bytes memory result) = token.staticcall(
            abi.encodeWithSignature("decimals()")
        );
        if (!success || result.length != 32) {
            revert IBondingRegistry.BondingAssetDecimalsUnavailable(token);
        }
        uint256 decoded = abi.decode(result, (uint256));
        if (decoded > type(uint8).max) {
            revert IBondingRegistry.BondingAssetDecimalsUnavailable(token);
        }
        uint8 actualDecimals = uint8(decoded);
        if (actualDecimals != expectedDecimals) {
            revert IBondingRegistry.BondingAssetDecimalsMismatch(
                token,
                expectedDecimals,
                actualDecimals
            );
        }
    }

    function _slashingLayout()
        private
        pure
        returns (BondingSlashingStorage.Layout storage state)
    {
        bytes32 slot = BONDING_SLASHING_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            state.slot := slot
        }
    }

    function lockedBalanceOf(
        address token,
        address account
    ) public view returns (uint256) {
        (bool success, bytes memory result) = token.staticcall(
            abi.encodeCall(
                ILockAwareCiphernodeBondToken.lockedBalanceOf,
                (account)
            )
        );
        if (!success || result.length != 32) {
            revert IBondingRegistry.IncompatibleCiphernodeBondToken(token);
        }
        return abi.decode(result, (uint256));
    }

    /// @notice Preserves the previous owner's locked-FOLD coverage during an ownership transfer.
    function validateBondOwnerTransfer(
        address token,
        address previousOwner,
        uint256 bonded,
        uint256 delegatedBond
    ) external view {
        if (delegatedBond == 0) return;
        uint256 remainingBonded = bonded - delegatedBond;
        uint256 locked = lockedBalanceOf(token, previousOwner);
        uint256 controlled = IERC20(token).balanceOf(previousOwner) +
            remainingBonded;
        if (locked > controlled) {
            revert IBondingRegistry.BondOwnerTransferViolatesLock(
                previousOwner,
                locked,
                controlled
            );
        }
    }

    function transferExact(
        address tokenAddress,
        address recipient,
        uint256 amount
    ) external {
        _transferExact(tokenAddress, recipient, amount);
    }

    function transferFromExact(
        address tokenAddress,
        address sender,
        uint256 amount
    ) external {
        IERC20 token = IERC20(tokenAddress);
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(sender, address(this), amount);
        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 received = balanceAfter > balanceBefore
            ? balanceAfter - balanceBefore
            : 0;
        if (received != amount) {
            revert IBondingRegistry.AssetTransferMismatch(
                tokenAddress,
                amount,
                received
            );
        }
    }

    function sweepCiphernodeBondSurplus(
        address tokenAddress,
        address registry,
        address treasury,
        uint256 liabilities
    ) external returns (uint256 amount) {
        if (tokenAddress == address(0)) return 0;
        IERC20 token = IERC20(tokenAddress);
        uint256 balance = token.balanceOf(registry);
        if (balance <= liabilities) return 0;

        amount = balance - liabilities;
        _transferExact(tokenAddress, treasury, amount);
        emit IBondingRegistry.CiphernodeBondSurplusSwept(
            tokenAddress,
            treasury,
            amount
        );
    }

    function _transferExact(
        address tokenAddress,
        address recipient,
        uint256 amount
    ) private {
        IERC20 token = IERC20(tokenAddress);
        uint256 custodyBefore = token.balanceOf(address(this));
        uint256 recipientBefore = token.balanceOf(recipient);
        token.safeTransfer(recipient, amount);
        uint256 recipientAfter = token.balanceOf(recipient);
        uint256 received = recipientAfter > recipientBefore
            ? recipientAfter - recipientBefore
            : 0;
        if (received != amount) {
            revert IBondingRegistry.AssetTransferMismatch(
                tokenAddress,
                amount,
                received
            );
        }
        uint256 custodyAfter = token.balanceOf(address(this));
        uint256 spent = custodyBefore > custodyAfter
            ? custodyBefore - custodyAfter
            : 0;
        if (spent != amount) {
            revert IBondingRegistry.AssetTransferMismatch(
                tokenAddress,
                amount,
                spent
            );
        }
    }
}
