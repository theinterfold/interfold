// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Minimal ERC-20 that redirects a configurable basis-point fee to a
///         dead-address sink (`0xdead`) on every `transfer` / `transferFrom`
///         (total supply is unchanged; the fee portion is not actually burned).
///         Used in tests to validate that the BondingRegistry's license-payout
///         paths detect short transfers.
contract MockFeeOnTransferToken is ERC20 {
    uint256 public feeBps;

    constructor(uint256 _feeBps) ERC20("FoT", "FoT") {
        require(_feeBps <= 10_000, "fee>100%");
        feeBps = _feeBps;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setFeeBps(uint256 newFeeBps) external {
        require(newFeeBps <= 10_000, "fee>100%");
        feeBps = newFeeBps;
    }

    function _update(
        address from,
        address to,
        uint256 value
    ) internal override {
        if (from == address(0) || to == address(0) || feeBps == 0) {
            super._update(from, to, value);
            return;
        }
        uint256 fee = (value * feeBps) / 10_000;
        uint256 net = value - fee;
        super._update(from, to, net);
        if (fee > 0) {
            super._update(from, address(0xdead), fee);
        }
    }
}
