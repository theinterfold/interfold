// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IBondingAdmission } from "../interfaces/IBondingAdmission.sol";
import {
    BondingAdmissionStorage
} from "../storage/BondingAdmissionStorage.sol";
import { BondOwnerCapacityLib } from "./BondOwnerCapacityLib.sol";

/// @notice Keeps admission separate from current collateral and release eligibility.
library BondingAdmissionLib {
    using Checkpoints for Checkpoints.Trace208;

    function layout()
        internal
        pure
        returns (BondingAdmissionStorage.AdmissionLayout storage state)
    {
        // ERC-7201: interfold.storage.BondingAdmission
        bytes32 slot = keccak256(
            abi.encode(
                uint256(keccak256("interfold.storage.BondingAdmission")) - 1
            )
        ) & ~bytes32(uint256(0xff));
        // solhint-disable-next-line no-inline-assembly
        assembly {
            state.slot := slot
        }
    }

    function policyAt(
        uint256 timepoint
    ) internal view returns (IBondingAdmission.AdmissionPolicy memory) {
        BondingAdmissionStorage.AdmissionLayout storage state = layout();
        return
            state.policies[
                state.policyVersions.upperLookupRecent(
                    SafeCast.toUint48(timepoint)
                )
            ];
    }

    function setPolicy(bool enabled, uint48 duration, bool paused) internal {
        BondingAdmissionStorage.AdmissionLayout storage state = layout();
        uint208 version = state.policyVersions.latest();
        IBondingAdmission.AdmissionPolicy memory policy = state.policies[
            version
        ];
        if (
            policy.cooldownEnabled == enabled &&
            policy.cooldownDuration == duration &&
            policy.admissionsPaused == paused
        ) return;
        if (paused && !policy.admissionsPaused) {
            // Freeze the eligible pool before the pause transaction's timestamp.
            uint48 boundary = SafeCast.toUint48(block.timestamp - 1);
            IBondingAdmission.AdmissionPolicy memory beforePause = policyAt(
                boundary
            );
            // Multiple changes in one block cannot widen the pre-block pool.
            policy.pauseTimepoint = beforePause.admissionsPaused
                ? beforePause.pauseTimepoint
                : boundary;
            policy.pauseCooldownEnabled = beforePause.admissionsPaused
                ? beforePause.pauseCooldownEnabled
                : beforePause.cooldownEnabled;
            policy.pauseCooldownDuration = beforePause.admissionsPaused
                ? beforePause.pauseCooldownDuration
                : beforePause.cooldownDuration;
        } else if (!paused) {
            policy.pauseTimepoint = 0;
            policy.pauseCooldownEnabled = false;
            policy.pauseCooldownDuration = 0;
        }
        policy.cooldownEnabled = enabled;
        policy.cooldownDuration = duration;
        policy.admissionsPaused = paused;
        state.policies[version + 1] = policy;
        state.policyVersions.push(
            SafeCast.toUint48(block.timestamp),
            version + 1
        );
        BondOwnerCapacityLib.reset();
        emit IBondingAdmission.AdmissionPolicyUpdated(
            SafeCast.toUint48(block.timestamp),
            policy
        );
    }

    /// @notice Records each registration and actual owner change, even when disabled.
    function start(address operator) internal {
        uint48 timepoint = SafeCast.toUint48(block.timestamp);
        layout().positionStarts[operator].push(timepoint, timepoint);
        emit IBondingAdmission.AdmissionStarted(operator, timepoint);
    }

    function allows(
        address operator,
        uint256 timepoint,
        IBondingAdmission.AdmissionPolicy memory policy
    ) internal view returns (bool) {
        uint256 since = layout().positionStarts[operator].upperLookupRecent(
            SafeCast.toUint48(timepoint)
        );
        uint256 boundary = policy.admissionsPaused
            ? policy.pauseTimepoint
            : timepoint;
        if (since > boundary) return false;
        bool enabled = policy.admissionsPaused
            ? policy.pauseCooldownEnabled
            : policy.cooldownEnabled;
        uint256 duration = policy.admissionsPaused
            ? policy.pauseCooldownDuration
            : policy.cooldownDuration;
        // Unchanged pre-upgrade positions retain admission; their age is unknown.
        return since == 0 || !enabled || boundary - since >= duration;
    }

    function capacityPolicyMatches(
        uint256 timepoint
    ) internal view returns (bool) {
        Checkpoints.Trace208 storage versions = layout().policyVersions;
        return
            versions.upperLookupRecent(SafeCast.toUint48(timepoint)) ==
            versions.latest();
    }
}
