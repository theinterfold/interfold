// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../../interfaces/IDecryptionVerifier.sol";

interface IBfvDecryptionVerifierRoute is IDecryptionVerifier {
    function expectedC6FoldKeyHash() external view returns (bytes32);
    function expectedC7KeyHash() external view returns (bytes32);
}

/// @notice Dispatches BFV decryption proofs to the verifier that matches their VK anchors.
contract BfvDecryptionVerifierRouter is IDecryptionVerifier {
    error EmptyVerifierRoutes();
    error InvalidVerifierRoute(address verifier);

    struct Route {
        IBfvDecryptionVerifierRoute verifier;
        uint256 expectedPublicInputsLen;
        bytes32 expectedC6FoldKeyHash;
        bytes32 expectedC7KeyHash;
    }

    /// @notice Default reconstruction threshold used by Interfold verifier admission checks.
    uint256 public immutable override threshold;

    Route[] private routes;

    constructor(address[] memory verifiers, uint256 defaultThreshold) {
        if (verifiers.length == 0 || defaultThreshold == 0) {
            revert EmptyVerifierRoutes();
        }
        threshold = defaultThreshold;

        for (uint256 i = 0; i < verifiers.length; ++i) {
            address verifier = verifiers[i];
            if (verifier.code.length == 0) {
                revert InvalidVerifierRoute(verifier);
            }
            IBfvDecryptionVerifierRoute route = IBfvDecryptionVerifierRoute(
                verifier
            );
            uint256 routeThreshold = route.threshold();
            if (routeThreshold == 0) revert InvalidVerifierRoute(verifier);
            routes.push(
                Route({
                    verifier: route,
                    // BfvDecryptionVerifier: 7 + 1 + 3 * (T + 1) + 50 message coefficients.
                    expectedPublicInputsLen: 61 + (3 * routeThreshold),
                    expectedC6FoldKeyHash: route.expectedC6FoldKeyHash(),
                    expectedC7KeyHash: route.expectedC7KeyHash()
                })
            );
        }
    }

    function routeCount() external view returns (uint256) {
        return routes.length;
    }

    function routeAt(
        uint256 index
    )
        external
        view
        returns (
            address verifier,
            uint256 expectedPublicInputsLen,
            bytes32 expectedC6FoldKeyHash,
            bytes32 expectedC7KeyHash
        )
    {
        Route storage route = routes[index];
        return (
            address(route.verifier),
            route.expectedPublicInputsLen,
            route.expectedC6FoldKeyHash,
            route.expectedC7KeyHash
        );
    }

    /// @inheritdoc IDecryptionVerifier
    function verify(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view override returns (bool success) {
        (bytes memory rawProof, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );
        rawProof;

        if (publicInputs.length < 2) {
            revert InvalidPublicInputsLength();
        }

        bool lengthMatched;
        for (uint256 i = 0; i < routes.length; ++i) {
            Route storage route = routes[i];
            if (publicInputs.length != route.expectedPublicInputsLen) {
                continue;
            }
            lengthMatched = true;
            if (
                publicInputs[0] != route.expectedC6FoldKeyHash ||
                publicInputs[1] != route.expectedC7KeyHash
            ) {
                continue;
            }
            return
                route.verifier.verify(
                    e3Id,
                    decryptionDomain,
                    plaintextOutputHash,
                    committeeHash,
                    ciphertextCommitment,
                    proof
                );
        }

        if (lengthMatched) revert VkHashMismatch();
        revert InvalidPublicInputsLength();
    }
}
