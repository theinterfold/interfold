// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import {
    IE3ProgramDataAvailability
} from "../interfaces/IDataAvailabilityVerifier.sol";
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @dev Test-only ERC-165 probe that can advertise each required E3 program interface separately.
contract MockE3ProgramInterfaceProbe is IERC165 {
    bool private immutable program;
    bool private immutable availability;

    constructor(bool _program, bool _availability) {
        program = _program;
        availability = _availability;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) external view returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId ||
            (program && interfaceId == type(IE3Program).interfaceId) ||
            (availability &&
                interfaceId == type(IE3ProgramDataAvailability).interfaceId);
    }
}
