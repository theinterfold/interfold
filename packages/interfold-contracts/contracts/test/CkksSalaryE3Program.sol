// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";
import { CkksAppE3ProgramBase } from "./CkksAppE3ProgramBase.sol";

/// @title CkksSalaryE3Program
/// @notice Private salary survey (CKKS ParamSet 3). A submission is
///         accepted only with the two Greco legs AND the
///         `ckks_salary_validity_ps3` proof that the encrypted, slot-
///         replicated value is `salary / cap` with `0 <= salary <= cap`.
///
///         App-leg public inputs: `[cap, m_commitment]`. The cap is fixed
///         at deployment (the demo's public normalization cap), so every
///         accepted salary is a fraction of the same cap and the packed
///         statistics policy can decode against it.
contract CkksSalaryE3Program is CkksAppE3ProgramBase {
    /// @dev `[cap, m_commitment]`.
    uint256 internal constant APP_PUBLIC_INPUTS = 2;

    /// @notice The public normalization cap every submission must use.
    uint256 public immutable salaryCap;

    error WrongCap(uint256 got, uint256 want);

    constructor(
        IHonkVerifier ct0Verifier_,
        IHonkVerifier ct1Verifier_,
        IHonkVerifier appVerifier_,
        uint256 salaryCap_
    ) CkksAppE3ProgramBase(ct0Verifier_, ct1Verifier_, appVerifier_) {
        salaryCap = salaryCap_;
    }

    /// @inheritdoc IE3Program
    /// @dev See `CkksAppE3ProgramBase._publishThreeLegInput` for the
    ///      `data` envelope.
    function publishInput(uint256 e3Id, bytes memory data) external {
        _publishThreeLegInput(e3Id, data);
    }

    function _appPublicInputCount() internal pure override returns (uint256) {
        return APP_PUBLIC_INPUTS;
    }

    function _checkAppPublicInputs(
        uint256,
        bytes32[] memory appPublicInputs
    ) internal view override {
        uint256 cap = uint256(appPublicInputs[0]);
        if (cap != salaryCap) revert WrongCap(cap, salaryCap);
    }
}
