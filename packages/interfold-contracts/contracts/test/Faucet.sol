// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Faucet {
    IERC20 public fold;
    IERC20 public feeToken;

    uint256 public constant AMOUNT_FOLD = 200e18;
    uint256 public constant AMOUNT_FEE_TOKEN = 200e6;

    constructor(address _fold, address _feeToken) payable {
        fold = IERC20(_fold);
        feeToken = IERC20(_feeToken);
    }

    function faucet() external {
        // Top up each token independently: a tester who spent their fee
        // tokens but still holds FOLD must still be able to replenish the
        // fee token (and vice versa).
        bool needsFold = fold.balanceOf(msg.sender) < AMOUNT_FOLD;
        bool needsFeeToken = feeToken.balanceOf(msg.sender) < AMOUNT_FEE_TOKEN;

        if (!needsFold && !needsFeeToken) {
            revert("You have enough tokens");
        }

        if (needsFold) {
            if (fold.balanceOf(address(this)) < AMOUNT_FOLD) {
                revert("No FOLD");
            }
            fold.transfer(msg.sender, AMOUNT_FOLD);
        }

        if (needsFeeToken) {
            if (feeToken.balanceOf(address(this)) < AMOUNT_FEE_TOKEN) {
                revert("No feeToken");
            }
            feeToken.transfer(msg.sender, AMOUNT_FEE_TOKEN);
        }
    }
}
