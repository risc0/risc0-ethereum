use alloy_primitives::{address, Address};
use alloy_sol_types::sol;

/// Address of Compound USDC.
pub const CONTRACT: Address = address!("39aa39c021dfbae8fac545936693ac917d5e7563");

sol! {
    /// Simplified interface of Uniswap pair contract using only what is needed.
    interface CToken {
        function supplyRatePerBlock() external view returns (uint);
        function getUtilization() public view returns (uint);
    }
}
