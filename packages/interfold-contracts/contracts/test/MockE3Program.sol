// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import {
    IDataAvailabilityVerifier,
    IE3ProgramDataAvailability
} from "../interfaces/IDataAvailabilityVerifier.sol";

/// @title MockE3Program
/// @notice Provides a stateless BFV program for bootstrap deployments and protocol tests.
/// @dev This contract applies no application-specific input or output rules. Its deterministic
///      receipt is not production data availability. Keep requests paused until a production E3
///      program is registered and wired. Interfold still verifies the BFV protocol proofs.
contract MockE3Program is IE3Program, IE3ProgramDataAvailability {
    error InvalidDataAvailabilityProof();

    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");

    /// @notice Emitted when a caller publishes test input data.
    event InputPublished(
        uint256 indexed e3Id,
        address indexed publisher,
        bytes data
    );

    /// @inheritdoc IE3Program
    function validate(
        uint256,
        uint256,
        bytes calldata,
        bytes calldata,
        bytes calldata
    ) external pure returns (bytes32) {
        return ENCRYPTION_SCHEME_ID;
    }

    /// @inheritdoc IE3Program
    function publishInput(uint256 e3Id, bytes memory data) external {
        emit InputPublished(e3Id, msg.sender, data);
    }

    /// @inheritdoc IE3Program
    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes memory
    ) external pure returns (bool success) {
        return true;
    }

    /// @inheritdoc IE3ProgramDataAvailability
    /// @dev Local and bootstrap deployments use the object bytes as their deterministic receipt.
    function verifyDataAvailability(
        bytes32 expectedContentHash,
        bytes calldata proof
    )
        external
        pure
        returns (IDataAvailabilityVerifier.DataReference memory receipt)
    {
        if (keccak256(proof) != expectedContentHash)
            revert InvalidDataAvailabilityProof();
        return
            IDataAvailabilityVerifier.DataReference({
                contentHash: expectedContentHash,
                blockNumber: 1,
                leafIndex: 1
            });
    }
}
