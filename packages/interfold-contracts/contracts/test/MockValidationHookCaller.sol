// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

interface IMockValidationHook {
    function validate(
        uint256 maxPrice,
        uint128 amount,
        address owner,
        address sender,
        bytes calldata hookData
    ) external;
}

contract MockValidationHookCaller {
    function callValidate(
        address hook,
        uint256 maxPrice,
        uint128 amount,
        address owner,
        address sender,
        bytes calldata hookData
    ) external {
        IMockValidationHook(hook).validate(
            maxPrice,
            amount,
            owner,
            sender,
            hookData
        );
    }
}
