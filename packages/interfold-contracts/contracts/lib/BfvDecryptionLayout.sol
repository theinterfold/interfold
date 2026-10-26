// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { BfvProtocol } from "./BfvProtocol.sol";

/// @dev Application inputs only; Honk's pairing-point fields are not supplied by callers.
library BfvDecryptionLayout {
    function partyIdOffset() internal pure returns (uint256) {
        return
            BfvProtocol.DEC_PUBLIC_INPUT_COUNT +
            BfvProtocol.DEC_RETURN_PREFIX_LEN;
    }

    function skOffset(uint256 threshold) internal pure returns (uint256) {
        return partyIdOffset() + (threshold + 1);
    }

    function esmOffset(uint256 threshold) internal pure returns (uint256) {
        return skOffset(threshold) + (threshold + 1);
    }

    function messageOffset(uint256 threshold) internal pure returns (uint256) {
        return
            partyIdOffset() +
            BfvProtocol.DEC_RETURN_COLUMN_COUNT *
            (threshold + 1);
    }

    function publicInputsLength(
        uint256 threshold
    ) internal pure returns (uint256) {
        return messageOffset(threshold) + BfvProtocol.MESSAGE_COEFFS_COUNT;
    }
}
