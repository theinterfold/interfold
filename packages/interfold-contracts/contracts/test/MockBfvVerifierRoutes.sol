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
    error UnexpectedCall();

    uint256 public immutable override h;
    bytes32 public immutable override expectedNodesFoldKeyHash;
    bytes32 public immutable override expectedC5KeyHash;
    bool private immutable result;
    bytes32 private expectedCallHash;

    constructor(
        uint256 _h,
        bytes32 _expectedNodesFoldKeyHash,
        bytes32 _expectedC5KeyHash,
        bool _result
    ) {
        h = _h;
        expectedNodesFoldKeyHash = _expectedNodesFoldKeyHash;
        expectedC5KeyHash = _expectedC5KeyHash;
        result = _result;
    }

    /// @dev Makes `verify` revert unless its calldata equals `data`.
    function expectCall(bytes calldata data) external {
        expectedCallHash = keccak256(data);
    }

    function verify(
        uint256,
        uint256,
        address[] calldata,
        bytes32,
        bytes32,
        bytes calldata
    ) external view override returns (bool success) {
        if (expectedCallHash != 0 && keccak256(msg.data) != expectedCallHash)
            revert UnexpectedCall();
        success = result;
    }
}

contract MockBfvDecryptionVerifierRoute is IBfvDecryptionVerifierRoute {
    error UnexpectedCall();

    uint256 public immutable override threshold;
    bytes32 public immutable override expectedC6FoldKeyHash;
    bytes32 public immutable override expectedC7KeyHash;
    bool private immutable result;
    bytes32 private expectedCallHash;

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

    /// @dev Makes `verify` revert unless its calldata equals `data`.
    function expectCall(bytes calldata data) external {
        expectedCallHash = keccak256(data);
    }

    function verify(
        uint256,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        bytes calldata
    ) external view override returns (bool success) {
        if (expectedCallHash != 0 && keccak256(msg.data) != expectedCallHash)
            revert UnexpectedCall();
        success = result;
    }
}
