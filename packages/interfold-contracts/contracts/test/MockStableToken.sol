// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract MockUSDC is ERC20, Ownable {
    // solhint-disable-next-line immutable-vars-naming
    uint8 private immutable _decimals;

    constructor(
        uint256 initialSupply
    ) ERC20("USD Coin", "USDC") Ownable(msg.sender) {
        _decimals = 6;
        _mint(msg.sender, initialSupply * 10 ** _decimals);
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
