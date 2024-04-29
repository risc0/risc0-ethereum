use alloy_primitives::{address, Address};
use alloy_sol_types::sol;

/// Address of Eth/USDC Uniswap pair
pub const CONTRACT: Address = address!("B4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc");
/// Function to call
pub const CALL: IUniswapV2Pair::getReservesCall = IUniswapV2Pair::getReservesCall {};
/// Caller address
pub const CALLER: Address = address!("f08A50178dfcDe18524640EA6618a1f965821715");

sol! {
    /// Simplified interface of Uniswap pair contract using only what is needed.
    interface IUniswapV2Pair {
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    }
}
