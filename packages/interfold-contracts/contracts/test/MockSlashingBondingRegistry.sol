// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Records slashing calls without holding or transferring collateral.
contract MockSlashingBondingRegistry {
    uint64 public constant bondingAssetConfigurationVersion = 1;
    uint256 public ticketPenaltyRequested;
    uint256 public bondPenaltyRequested;
    uint256 public openLocks;

    function snapshotSlashRouteDestination(
        uint256,
        address,
        address
    ) external {}

    function openSlashLock(uint256, uint256, address) external {
        openLocks++;
    }

    function closeSlashLock(uint256, address) external {
        openLocks--;
    }

    function slashTicketBalance(
        address,
        uint256 amount,
        bytes32
    ) external returns (uint256) {
        ticketPenaltyRequested += amount;
        return 0;
    }

    function slashCiphernodeBond(
        address,
        uint256 amount,
        bytes32
    ) external returns (uint256) {
        bondPenaltyRequested += amount;
        return 0;
    }
}
