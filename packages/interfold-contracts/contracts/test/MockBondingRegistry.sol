// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Minimal mock BondingRegistry for standalone InterfoldToken tests.
///         Returns 0 for totalBonded so locked-balance enforcement works
///         without a full system deployment.
contract MockBondingRegistry {
    function totalBonded(
        address /* account */
    ) external pure returns (uint256) {
        return 0;
    }
}
