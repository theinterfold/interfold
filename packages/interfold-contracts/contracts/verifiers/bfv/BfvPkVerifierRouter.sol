// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IPkVerifier } from "../../interfaces/IPkVerifier.sol";

interface IBfvPkVerifierRoute is IPkVerifier {
    function expectedNodesFoldKeyHash() external view returns (bytes32);
    function expectedC5KeyHash() external view returns (bytes32);
}

/// @notice Dispatches BFV DKG proofs to the verifier that matches their VK anchors.
contract BfvPkVerifierRouter is IPkVerifier {
    error EmptyVerifierRoutes();
    error InvalidVerifierRoute(address verifier);

    struct Route {
        IBfvPkVerifierRoute verifier;
        uint256 expectedPublicInputsLen;
        bytes32 expectedNodesFoldKeyHash;
        bytes32 expectedC5KeyHash;
    }

    /// @notice Default honest-party count used by Interfold verifier admission checks.
    uint256 public immutable override h;

    Route[] private routes;

    constructor(address[] memory verifiers, uint256 defaultH) {
        if (verifiers.length == 0 || defaultH == 0) {
            revert EmptyVerifierRoutes();
        }
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
                    expectedPublicInputsLen: (3 * routeH) + 24,
                    expectedNodesFoldKeyHash: route.expectedNodesFoldKeyHash(),
                    expectedC5KeyHash: route.expectedC5KeyHash()
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
            bytes32 expectedC5KeyHash
        )
    {
        Route storage route = routes[index];
        return (
            address(route.verifier),
            route.expectedPublicInputsLen,
            route.expectedNodesFoldKeyHash,
            route.expectedC5KeyHash
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
                publicInputs[0] != route.expectedNodesFoldKeyHash ||
                publicInputs[1] != route.expectedC5KeyHash
            ) {
                continue;
            }
            return
                route.verifier.verify(
                    e3Id,
                    committeeRoot,
                    sortedNodes,
                    pkCommitment,
                    committeeHash,
                    proof
                );
        }

        if (lengthMatched) revert VkHashMismatch();
        revert InvalidPublicInputsLength();
    }
}
