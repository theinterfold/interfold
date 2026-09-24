// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { IBondingAdmission } from "../interfaces/IBondingAdmission.sol";

abstract contract BondingAdmissionStorage {
    /// @custom:storage-location erc7201:interfold.storage.BondingAdmission
    struct AdmissionLayout {
        Checkpoints.Trace208 policyVersions;
        mapping(uint208 version => IBondingAdmission.AdmissionPolicy policy) policies;
        mapping(address operator => Checkpoints.Trace208 starts) positionStarts;
    }
}
