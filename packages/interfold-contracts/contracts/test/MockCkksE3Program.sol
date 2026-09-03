// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";

/// @title MockCkksE3Program
/// @notice Stateless CKKS program for protocol tests: the program address
///         IS the protocol selector — requesting an E3 with this program
///         binds `keccak256("fhe.rs:CKKS")` as the encryption scheme, so a
///         requester only supplies committee size and paramSet, and every
///         downstream component (verifier lookup, ciphernode dispatch)
///         keys off the program-bound scheme id.
/// @dev Mirror of `MockE3Program` with the CKKS scheme id. The plaintext
///      output for CKKS E3s is the canonical fixed-point encoding
///      (`CkksFixedPointLib`).
contract MockCkksE3Program is IE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:CKKS");

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
}
