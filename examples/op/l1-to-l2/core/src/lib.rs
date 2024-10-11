use alloy_primitives::{address, Address};
use alloy_sol_types::sol;

sol! {
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Function to call, implements the `SolCall` trait.
pub const CALL: IERC20::balanceOfCall = IERC20::balanceOfCall {
    account: address!("F977814e90dA44bFA03b6295A0616a897441aceC"),
};

/// Address of the deployed contract to call the function on (USDT contract on Eth Mainnet).
pub const CONTRACT: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");

pub const CALLER: Address = Address::ZERO;
