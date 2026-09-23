// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Historical bond ownership for request-time committee admission.
interface IBondOwnerHistory {
    /// @notice Returns the bond owner at an EIP-6372 timestamp.
    /// @dev History starts at the upgrade. Earlier rounds retain their old admission rules.
    function bondOwnerAt(
        address operator,
        uint256 timepoint
    ) external view returns (address);
}
