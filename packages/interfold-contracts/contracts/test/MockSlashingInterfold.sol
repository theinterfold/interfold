// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

import { E3 } from "../interfaces/IE3.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { ISlashingManager } from "../interfaces/ISlashingManager.sol";

contract MockSlashingInterfold {
    mapping(uint256 e3Id => uint256 deadline) private _lifecycleDeadlines;
    mapping(uint256 e3Id => uint8 paramSet) private _paramSets;

    function setParamSet(uint256 e3Id, uint8 paramSet) external {
        _paramSets[e3Id] = paramSet;
    }

    /// @dev Only `paramSet` is meaningful: it is the sole E3 field the slashing evidence
    ///      library reads.
    function getE3(uint256 e3Id) external view returns (E3 memory e3) {
        e3.paramSet = _paramSets[e3Id];
    }

    function snapshotDependencies(
        ISlashingManager manager,
        uint256 e3Id,
        uint256 lifecycleDeadline
    ) external {
        _lifecycleDeadlines[e3Id] = lifecycleDeadline;
        manager.snapshotE3Dependencies(e3Id);
    }

    function getE3LifecycleDeadline(
        uint256 e3Id
    ) external view returns (uint256) {
        return _lifecycleDeadlines[e3Id];
    }

    function getE3Stage(uint256) external pure returns (IInterfold.E3Stage) {
        return IInterfold.E3Stage.Failed;
    }
}
