// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "./IE3Program.sol";
import { IDecryptionVerifier } from "./IDecryptionVerifier.sol";
import { IPkVerifier } from "./IPkVerifier.sol";
import { IInterfold } from "./IInterfold.sol";

/**
 * @title E3
 * @notice Represents a complete E3 (Encrypted Execution Environment) computation request and its lifecycle
 * @dev This struct tracks all parameters, state, and results of an encrypted computation
 *      from request through completion
 * @param seed Random seed for committee selection and computation initialization
 * @param committeeSize The committee size enum value for this computation
 * @param requestBlock Block number when the E3 computation was requested
 * @param inputWindow When to start and stop accepting inputs from data providers
 * @param encryptionSchemeId Identifier for the encryption scheme used in this computation
 * @param e3Program Address of the E3 Program contract that validates and verifies the computation
 * @param paramSet BFV encryption parameter set used for this computation
 * @param customParams Arbitrary ABI-encoded application-defined parameters.
 * @param decryptionVerifier Address of the output verifier contract for decryption verification
 * @param committeePublicKey Hash of the public key of the selected committee for this computation
 * @param ciphertextOutput Hash of the encrypted output data produced by the computation
 * @param plaintextOutput Decrypted output data after committee decryption
 * @param requester Address of the entity that requested the E3 computation
 */
struct E3 {
    uint256 seed;
    IInterfold.CommitteeSize committeeSize;
    uint256 requestBlock;
    uint256[2] inputWindow;
    bytes32 encryptionSchemeId;
    IE3Program e3Program;
    uint8 paramSet;
    bytes customParams;
    IDecryptionVerifier decryptionVerifier;
    IPkVerifier pkVerifier;
    bytes32 committeePublicKey;
    bytes32 ciphertextOutput;
    bytes plaintextOutput;
    address requester;
    bool proofAggregationEnabled;
}
