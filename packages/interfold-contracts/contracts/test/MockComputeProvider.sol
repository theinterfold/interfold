// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    IComputeProvider,
    IDecryptionVerifier
} from "../interfaces/IComputeProvider.sol";

contract MockComputeProvider is IComputeProvider {
    error InvalidParams();

    function validate(
        uint256,
        uint256,
        bytes memory params
    ) external pure returns (IDecryptionVerifier decryptionVerifier) {
        require(params.length == 32, InvalidParams());
        // solhint-disable no-inline-assembly
        assembly {
            decryptionVerifier := mload(add(params, 32))
        }
        (decryptionVerifier) = abi.decode(params, (IDecryptionVerifier));
    }
}
