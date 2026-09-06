// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "../interfaces/IE3.sol";

/**
 * @title MockParamSetSource
 * @notice Minimal `getE3` provider for the CKKS verifier specs.
 * @dev `CkksPkVerifier` / `CkksDecryptionVerifier` only read `e3.paramSet` from the
 *      Interfold deployment, so the specs need nothing more than a settable param
 *      set per E3 id. Deploying the full Interfold to exercise one struct field
 *      would make the specs slow and coupled to unrelated setup.
 */
contract MockParamSetSource {
    mapping(uint256 e3Id => uint8 paramSet) public paramSetOf;

    function setParamSet(uint256 e3Id, uint8 paramSet) external {
        paramSetOf[e3Id] = paramSet;
    }

    function getE3(uint256 e3Id) external view returns (E3 memory e3) {
        e3.paramSet = paramSetOf[e3Id];
    }
}
