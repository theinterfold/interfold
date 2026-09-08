// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import {
    IDataAvailabilityVerifier
} from "../interfaces/IDataAvailabilityVerifier.sol";

/// @notice Deterministic local-only replacement for Avail and VectorX.
contract MockDataAvailabilityVerifier is IDataAvailabilityVerifier {
    error ContentHashMismatch(bytes32 expected, bytes32 actual);

    /// @inheritdoc IDataAvailabilityVerifier
    function verifyDataAvailability(
        bytes32 expectedContentHash,
        bytes calldata proof
    ) external pure returns (DataReference memory receipt) {
        bytes32 actual = keccak256(proof);
        if (actual != expectedContentHash) {
            revert ContentHashMismatch(expectedContentHash, actual);
        }
        receipt = DataReference(expectedContentHash, 0, 0);
    }
}
