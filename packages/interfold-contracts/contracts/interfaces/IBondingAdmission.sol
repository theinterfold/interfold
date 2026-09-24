// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Governance policy for admission to future committees.
interface IBondingAdmission {
    struct AdmissionPolicy {
        bool cooldownEnabled;
        bool admissionsPaused;
        uint48 cooldownDuration;
        uint48 pauseTimepoint;
        bool pauseCooldownEnabled;
        uint48 pauseCooldownDuration;
    }

    event AdmissionPolicyUpdated(uint48 timepoint, AdmissionPolicy policy);
    event AdmissionStarted(address indexed operator, uint48 timepoint);

    /// @notice Changes future admission rules without changing existing E3 snapshots.
    function setAdmissionPolicy(
        bool cooldownEnabled,
        uint48 cooldownDuration,
        bool admissionsPaused
    ) external;

    /// @notice Returns the policy at a timestamp. An unset policy bypasses the cooldown.
    function admissionPolicyAt(
        uint256 timepoint
    ) external view returns (AdmissionPolicy memory);
}
