// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.27;

import { MockDataAvailabilityVerifier } from "@interfold/contracts/contracts/test/MockDataAvailabilityVerifier.sol";

/// @notice Makes the shared local DA mock available to the CRISP Hardhat project.
contract MockCrispDataAvailabilityVerifier is MockDataAvailabilityVerifier {}
