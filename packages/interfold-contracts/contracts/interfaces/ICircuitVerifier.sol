// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/**
 * @title ICircuitVerifier
 * @notice Interface for on-chain ZK circuit verifiers (e.g., DkgAggregatorVerifier, Honk verifiers)
 * @dev Standard interface matching the verification pattern used by Honk-generated verifiers.
 *      Set the circuit verifier address directly as the proofVerifier in a SlashPolicy.
 */
interface ICircuitVerifier {
    /// @notice Verify a ZK proof against public inputs
    /// @param _proof The raw proof bytes
    /// @param _publicInputs The public inputs to verify against
    /// @return True if the proof is valid
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool);
}
