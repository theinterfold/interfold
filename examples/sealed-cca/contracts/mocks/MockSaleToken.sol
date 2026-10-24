// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Demo and tests only: a sale token with 18 decimals. Anyone may mint.
contract MockSaleToken is ERC20 {
  constructor() ERC20("Mock Sale Token", "SALE") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}
