use alloy_primitives::{address, Address};
use alloy_sol_types::sol;
use risc0_steel::BlockCommitment;

/// Address of Compound USDC.
pub const CONTRACT: Address = address!("c3d688B66703497DAA19211EEdff47f25384cdc3");

sol! {
    /// Simplified interface of Uniswap pair contract using only what is needed.
    interface CToken {
        function getSupplyRate(uint utilization) virtual public view returns (uint64);
        function getUtilization() public view returns (uint);
    }
}

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct APRCommitment {
        BlockCommitment commitment;
        uint64 annualSupplyRate;
    }
}
