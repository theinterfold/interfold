// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../../interfaces/IDecryptionVerifier.sol";
import { ICiphernodeRegistry } from "../../interfaces/ICiphernodeRegistry.sol";

interface IBfvDecryptionVerifierRoute is IDecryptionVerifier {
    function expectedC6FoldKeyHash() external view returns (bytes32);
    function expectedC7KeyHash() external view returns (bytes32);
}

/// @notice Dispatches BFV decryption proofs to the verifier that matches the E3 parameter set and
///         VK anchors. The trBFV and l-BFV paths prove C7 with different circuits, so a route
///         accepts only E3s on its own parameter set.
contract BfvDecryptionVerifierRouter is IDecryptionVerifier {
    error EmptyVerifierRoutes();
    error InvalidRegistry(address registry);
    error InvalidRouteParamSets();
    error InvalidVerifierRoute(address verifier);
    error ParamSetRouteMismatch(uint8 paramSet);

    struct Route {
        IBfvDecryptionVerifierRoute verifier;
        uint256 expectedPublicInputsLen;
        bytes32 expectedC6FoldKeyHash;
        bytes32 expectedC7KeyHash;
        uint8 expectedParamSet;
    }

    /// @notice Default reconstruction threshold used by Interfold verifier admission checks.
    uint256 public immutable override threshold;

    /// @notice Registry used to resolve the parameter set frozen for an E3.
    ICiphernodeRegistry public immutable ciphernodeRegistry;

    Route[] private routes;

    constructor(
        address _ciphernodeRegistry,
        address[] memory verifiers,
        uint8[] memory expectedParamSets,
        uint256 defaultThreshold
    ) {
        if (_ciphernodeRegistry.code.length == 0) {
            revert InvalidRegistry(_ciphernodeRegistry);
        }
        if (verifiers.length == 0 || defaultThreshold == 0) {
            revert EmptyVerifierRoutes();
        }
        if (verifiers.length != expectedParamSets.length) {
            revert InvalidRouteParamSets();
        }
        ciphernodeRegistry = ICiphernodeRegistry(_ciphernodeRegistry);
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
                    expectedPublicInputsLen: 111 + (3 * routeThreshold),
                    expectedC6FoldKeyHash: route.expectedC6FoldKeyHash(),
                    expectedC7KeyHash: route.expectedC7KeyHash(),
                    expectedParamSet: expectedParamSets[i]
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
            bytes32 expectedC7KeyHash,
            uint8 expectedParamSet
        )
    {
        Route storage route = routes[index];
        return (
            address(route.verifier),
            route.expectedPublicInputsLen,
            route.expectedC6FoldKeyHash,
            route.expectedC7KeyHash,
            route.expectedParamSet
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
        IBfvDecryptionVerifierRoute verifier = _selectVerifier(e3Id, proof);
        return
            verifier.verify(
                e3Id,
                decryptionDomain,
                plaintextOutputHash,
                committeeHash,
                ciphertextCommitment,
                proof
            );
    }

    function _selectVerifier(
        uint256 e3Id,
        bytes calldata proof
    ) private view returns (IBfvDecryptionVerifierRoute) {
        (, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );

        if (publicInputs.length < 2) {
            revert InvalidPublicInputsLength();
        }

        uint8 paramSet = ciphernodeRegistry.interfold().getE3(e3Id).paramSet;
        bool lengthMatched;
        bool anchorsMatched;
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
            anchorsMatched = true;
            if (paramSet != route.expectedParamSet) {
                continue;
            }
            return route.verifier;
        }

        if (anchorsMatched) revert ParamSetRouteMismatch(paramSet);
        if (lengthMatched) revert VkHashMismatch();
        revert InvalidPublicInputsLength();
    }
}
