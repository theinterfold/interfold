// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "../interfaces/IE3.sol";

contract MockBfvV2Interfold {
    uint8 private immutable paramSet;

    constructor(uint8 value) {
        paramSet = value;
    }

    function getE3(uint256) external view returns (E3 memory) {
        E3 memory e3;
        e3.paramSet = paramSet;
        return e3;
    }
}
