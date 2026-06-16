// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockBlacklistUSDC
/// @notice USDC-style ERC20 with a USDC-style address blacklist used to prove
///         that pull-payment claim flows isolate failures: a blacklisted
///         recipient's failed claim must not block other claimants.
contract MockBlacklistUSDC is ERC20 {
    mapping(address => bool) public isBlacklisted;

    error Blacklisted(address account);

    constructor() ERC20("Blacklist USDC", "blUSDC") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function blacklist(address account) external {
        isBlacklisted[account] = true;
    }

    function unblacklist(address account) external {
        isBlacklisted[account] = false;
    }

    function _update(
        address from,
        address to,
        uint256 value
    ) internal override {
        // Skip blacklist check for mint (from == 0) and burn (to == 0)
        // so seeding/burning balances cannot be bricked by the mock.
        if (from != address(0) && isBlacklisted[from]) revert Blacklisted(from);
        if (to != address(0) && isBlacklisted[to]) revert Blacklisted(to);
        super._update(from, to, value);
    }
}
