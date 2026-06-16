// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "./IDecryptionVerifier.sol";

/**
 * @title IComputeProvider
 * @notice Interface for compute provider validation and configuration
 * @dev Compute providers define how computations are executed and verified in the E3 system
 */
interface IComputeProvider {
    /// @notice Validate compute provider parameters and return the appropriate decryption verifier
    /// @dev This function is called by the Interfold contract during E3 request to validate
    ///      compute provider configuration
    /// @param e3Id ID of the E3 computation
    /// @param seed Random seed for the computation
    /// @param params ABI encoded compute provider parameters
    /// @return decryptionVerifier The decryption verifier contract to use for this computation
    function validate(
        uint256 e3Id,
        uint256 seed,
        bytes calldata params
    ) external returns (IDecryptionVerifier decryptionVerifier);
}
