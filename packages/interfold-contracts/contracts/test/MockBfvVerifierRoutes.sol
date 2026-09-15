// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    IBfvDecryptionVerifierRoute
} from "../verifiers/bfv/BfvDecryptionVerifierRouter.sol";
import { IBfvPkVerifierRoute } from "../verifiers/bfv/BfvPkVerifierRouter.sol";

contract MockBfvPkVerifierRoute is IBfvPkVerifierRoute {
    uint256 public immutable override h;
    uint256 public immutable override expectedPublicInputsLen;
    bytes32 public immutable override expectedNodesFoldKeyHash;
    bytes32 public immutable override expectedC5KeyHash;
    bool private immutable result;

    constructor(
        uint256 _h,
        bytes32 _expectedNodesFoldKeyHash,
        bytes32 _expectedC5KeyHash,
        bool _result
    ) {
        h = _h;
        expectedPublicInputsLen = (3 * _h) + 24;
        expectedNodesFoldKeyHash = _expectedNodesFoldKeyHash;
        expectedC5KeyHash = _expectedC5KeyHash;
        result = _result;
    }

    function verify(
        uint256,
        uint256,
        address[] calldata,
        bytes32,
        bytes32,
        bytes calldata
    ) external view override returns (bool success) {
        success = result;
    }
}

contract MockBfvDecryptionVerifierRoute is IBfvDecryptionVerifierRoute {
    uint256 public immutable override threshold;
    bytes32 public immutable override expectedC6FoldKeyHash;
    bytes32 public immutable override expectedC7KeyHash;
    bool private immutable result;

    constructor(
        uint256 _threshold,
        bytes32 _expectedC6FoldKeyHash,
        bytes32 _expectedC7KeyHash,
        bool _result
    ) {
        threshold = _threshold;
        expectedC6FoldKeyHash = _expectedC6FoldKeyHash;
        expectedC7KeyHash = _expectedC7KeyHash;
        result = _result;
    }

    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        bytes calldata
    ) external view override returns (bool success) {
        success = result;
    }
}
