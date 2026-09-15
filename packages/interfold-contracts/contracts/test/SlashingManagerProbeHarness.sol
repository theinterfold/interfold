// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { SlashingManager } from "../slashing/SlashingManager.sol";
import { ICiphernodeRegistry } from "../interfaces/ICiphernodeRegistry.sol";

/// @dev Exposes `_committeeFinalized` so each revert shape the probe can meet
///      is pinned directly: the explicit `CommitteeNotFinalized()` must read as
///      "no committee"; anything else must fail closed and wait for the window.
contract SlashingManagerProbeHarness is SlashingManager {
    constructor() SlashingManager(0, msg.sender) {}

    function committeeFinalized(
        ICiphernodeRegistry registry,
        uint256 e3Id
    ) external view returns (bool) {
        return _committeeFinalized(registry, e3Id);
    }
}

/// @dev A registry stand-in that reverts however the test tells it to.
contract RevertingCanonicalRegistry {
    enum Mode {
        Answer,
        NotFinalized,
        OtherError,
        EmptyRevert,
        StringRevert
    }

    error SomethingElse(uint256 value);

    Mode public mode;

    function setMode(Mode newMode) external {
        mode = newMode;
    }

    function canonicalCommitteeNodeAt(
        uint256,
        uint256
    ) external view returns (address) {
        Mode current = mode;
        if (current == Mode.Answer) return address(this);
        if (current == Mode.NotFinalized)
            revert ICiphernodeRegistry.CommitteeNotFinalized();
        if (current == Mode.OtherError) revert SomethingElse(1);
        if (current == Mode.StringRevert) revert("no view here");
        // solhint-disable-next-line gas-custom-errors, reason-string
        revert();
    }
}
