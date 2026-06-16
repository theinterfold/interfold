// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IPkVerifier } from "../interfaces/IPkVerifier.sol";

contract MockPkVerifier is IPkVerifier {
    /// @dev Permissive test mock: only enforces the pk-commitment slot the
    ///      real wrapper enforces, so existing fixtures (`[pkCommitment]`)
    ///      keep working. Intentionally ignores VK-hash slots and domain
    ///      binding — those are exercised by `BfvPkVerifier.spec.ts` against
    ///      the real wrapper.
    function verify(
        uint256,
        uint256,
        address[] calldata,
        bytes32 pkCommitment,
        bytes32,
        bytes calldata proof
    ) external pure returns (bool) {
        (, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );
        if (publicInputs.length == 0) revert InvalidPublicInputsLength();
        if (publicInputs[publicInputs.length - 1] != pkCommitment) {
            revert PkCommitmentMismatch();
        }
        return true;
    }
}
