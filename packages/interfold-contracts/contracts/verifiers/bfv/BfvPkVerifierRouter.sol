// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IPkVerifier } from "../../interfaces/IPkVerifier.sol";
import { ICiphernodeRegistry } from "../../interfaces/ICiphernodeRegistry.sol";

interface IBfvPkVerifierRoute is IPkVerifier {
    function expectedNodesFoldKeyHash() external view returns (bytes32);
    function expectedC5KeyHash() external view returns (bytes32);
    function expectedPublicInputsLen() external view returns (uint256);
}

/// @notice Dispatches BFV DKG proofs to the verifier that matches the E3 parameter set and VK anchors.
contract BfvPkVerifierRouter is IPkVerifier {
    error EmptyVerifierRoutes();
    error InvalidRegistry(address registry);
    error InvalidRouteParamSets();
    error InvalidVerifierRoute(address verifier);
    error ParamSetRouteMismatch(uint8 paramSet);

    struct Route {
        IBfvPkVerifierRoute verifier;
        uint256 expectedPublicInputsLen;
        bytes32 expectedNodesFoldKeyHash;
        bytes32 expectedC5KeyHash;
        uint8 expectedParamSet;
    }

    /// @notice Default honest-party count used by Interfold verifier admission checks.
    uint256 public immutable override h;

    /// @notice Registry used to resolve the parameter set frozen for an E3.
    ICiphernodeRegistry public immutable ciphernodeRegistry;

    Route[] private routes;

    constructor(
        address _ciphernodeRegistry,
        address[] memory verifiers,
        uint8[] memory expectedParamSets,
        uint256 defaultH
    ) {
        if (_ciphernodeRegistry.code.length == 0) {
            revert InvalidRegistry(_ciphernodeRegistry);
        }
        if (verifiers.length == 0 || defaultH == 0) {
            revert EmptyVerifierRoutes();
        }
        if (verifiers.length != expectedParamSets.length) {
            revert InvalidRouteParamSets();
        }
        ciphernodeRegistry = ICiphernodeRegistry(_ciphernodeRegistry);
        h = defaultH;

        for (uint256 i = 0; i < verifiers.length; ++i) {
            address verifier = verifiers[i];
            if (verifier.code.length == 0) {
                revert InvalidVerifierRoute(verifier);
            }
            IBfvPkVerifierRoute route = IBfvPkVerifierRoute(verifier);
            uint256 routeH = route.h();
            if (routeH == 0) revert InvalidVerifierRoute(verifier);
            routes.push(
                Route({
                    verifier: route,
                    expectedPublicInputsLen: route.expectedPublicInputsLen(),
                    expectedNodesFoldKeyHash: route.expectedNodesFoldKeyHash(),
                    expectedC5KeyHash: route.expectedC5KeyHash(),
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
            bytes32 expectedNodesFoldKeyHash,
            bytes32 expectedC5KeyHash,
            uint8 expectedParamSet
        )
    {
        Route storage route = routes[index];
        return (
            address(route.verifier),
            route.expectedPublicInputsLen,
            route.expectedNodesFoldKeyHash,
            route.expectedC5KeyHash,
            route.expectedParamSet
        );
    }

    /// @inheritdoc IPkVerifier
    function verify(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 pkCommitment,
        bytes32 committeeHash,
        bytes calldata proof
    ) external view override returns (bool success) {
        IBfvPkVerifierRoute verifier = _selectVerifier(e3Id, proof);
        return
            verifier.verify(
                e3Id,
                committeeRoot,
                sortedNodes,
                pkCommitment,
                committeeHash,
                proof
            );
    }

    function _selectVerifier(
        uint256 e3Id,
        bytes calldata proof
    ) private view returns (IBfvPkVerifierRoute) {
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
                publicInputs[0] != route.expectedNodesFoldKeyHash ||
                publicInputs[1] != route.expectedC5KeyHash
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
