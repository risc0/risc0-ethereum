use alloy_primitives::{address, Address};
use alloy_sol_types::sol;

sol! {
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Function to call, implements the `SolCall` trait.
pub const CALL: IERC20::balanceOfCall = IERC20::balanceOfCall {
    account: address!("acD03D601e5bB1B275Bb94076fF46ED9D753435A"),
};

/// Address of the deployed contract to call the function on (USDT contract on OP Sepolia).
pub const CONTRACT: Address = address!("94b008aA00579c1307B0EF2c499aD98a8ce58e58");

pub const CALLER: Address = Address::ZERO;
