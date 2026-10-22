// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ActiveCryptoConfig } from "../lib/ActiveCryptoConfig.sol";
import { BfvProtocol } from "../lib/BfvProtocol.sol";

contract BfvProtocolHarness {
    function identity(
        uint8 paramSet
    )
        external
        pure
        returns (
            bytes32 scheme,
            bytes32 version,
            bytes32 params,
            bytes32 configId
        )
    {
        configId = ActiveCryptoConfig.configIdForParamSet(paramSet);
        params = paramSet == BfvProtocol.INSECURE_PARAM_SET
            ? BfvProtocol.INSECURE_PARAM_SET_HASH
            : BfvProtocol.SECURE_PARAM_SET_HASH;
        return (
            BfvProtocol.ENCRYPTION_SCHEME_ID,
            BfvProtocol.CIRCUIT_VERSION,
            params,
            configId
        );
    }

    function committee(
        uint8 size
    ) external pure returns (uint32 threshold, uint32 honest, uint32 total) {
        return ActiveCryptoConfig.committeeParams(size);
    }

    function dimensions()
        external
        pure
        returns (
            uint256 coefficients,
            uint256 coefficientBytes,
            uint256 fieldBytes,
            uint256 plaintextBytes
        )
    {
        return (
            BfvProtocol.MESSAGE_COEFFS_COUNT,
            BfvProtocol.MESSAGE_COEFF_BYTE_LEN,
            BfvProtocol.FIELD_BYTE_LEN,
            BfvProtocol.PLAINTEXT_BYTE_LEN
        );
    }
}
