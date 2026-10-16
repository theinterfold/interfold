// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Governance policy for bond-owner identity at committee request snapshots.
interface IBondingIdentity {
    struct IdentityPolicy {
        address registry;
        bool required;
    }

    event IdentityPolicyUpdated(
        uint48 timepoint,
        address registry,
        bool required
    );

    /// @notice A required policy needs a deployed registry; a call to an empty address would make
    ///         every eligibility check revert.
    error InvalidIdentityRegistry(address registry);

    /// @notice Sets the identity policy for future snapshots and clears counted owner capacity.
    function setIdentityPolicy(address registry, bool required) external;

    /// @notice Returns the policy at a timestamp. An unset policy does not require identity.
    function identityPolicyAt(
        uint256 timepoint
    ) external view returns (IdentityPolicy memory);
}
