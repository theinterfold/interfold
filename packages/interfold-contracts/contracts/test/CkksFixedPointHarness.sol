// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { CkksFixedPointLib } from "../lib/CkksFixedPointLib.sol";

/// @dev Test harness exposing the library's calldata functions externally.
contract CkksFixedPointHarness {
    function count(bytes calldata data) external pure returns (uint256) {
        return CkksFixedPointLib.count(data);
    }

    function valueAt(
        bytes calldata data,
        uint256 index
    ) external pure returns (int128) {
        return CkksFixedPointLib.valueAt(data, index);
    }

    function decodeAll(
        bytes calldata data
    ) external pure returns (int128[] memory) {
        return CkksFixedPointLib.decodeAll(data);
    }
}
