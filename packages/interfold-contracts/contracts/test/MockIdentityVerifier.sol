// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IIdentityVerifier } from "../interfaces/IIdentityVerifier.sol";

contract MockIdentityVerifier is IIdentityVerifier {
    struct Result {
        bytes32 identityId;
        uint48 expiresAt;
    }

    mapping(address owner => Result result) private _results;

    function setResult(
        address owner,
        bytes32 identityId,
        uint48 expiresAt
    ) external {
        _results[owner] = Result(identityId, expiresAt);
    }

    function verify(
        address owner,
        bytes calldata
    ) external view returns (bytes32 identityId, uint48 expiresAt) {
        Result storage result = _results[owner];
        return (result.identityId, result.expiresAt);
    }
}
