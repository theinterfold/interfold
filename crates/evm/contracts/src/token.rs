// SPDX-License-Identifier: LGPL-3.0-only

//! Token ABI surfaces used by operator commands, without wallet or command policy.

use alloy_sol_types::sol;

sol! {
    #[sol(rpc, abi)]
    interface IERC20Metadata {
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function decimals() external view returns (uint8);
        function symbol() external view returns (string memory);
        function name() external view returns (string memory);
    }

    #[sol(rpc, abi)]
    interface IInterfoldTicketToken {
        function underlying() external view returns (address);
    }
}
