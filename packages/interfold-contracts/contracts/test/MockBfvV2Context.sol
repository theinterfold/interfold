// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "../interfaces/IE3.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";

/// @dev Both values are immutables so the runtime code can be copied to another address with
///      `hardhat_setCode`, as the gas replay does.
contract MockBfvV2Interfold {
    uint8 private immutable paramSet;
    uint8 private immutable committeeSize;

    constructor(uint8 paramSetValue, uint8 committeeSizeValue) {
        paramSet = paramSetValue;
        committeeSize = committeeSizeValue;
    }

    function getE3(uint256) external view returns (E3 memory) {
        E3 memory e3;
        e3.paramSet = paramSet;
        e3.committeeSize = IInterfold.CommitteeSize(committeeSize);
        return e3;
    }
}
