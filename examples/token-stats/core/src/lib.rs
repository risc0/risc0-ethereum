// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::sol;
use risc0_steel::{ethereum::EthEvmChainInput, SolCommitment};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

/// Address of Compound USDC (cUSDCv3) token.
pub const CONTRACT: Address = address!("c3d688B66703497DAA19211EEdff47f25384cdc3");

sol! {
    /// Simplified interface of the Compound Finance Comet contract
    interface CometMainInterface {
        function getSupplyRate(uint utilization) virtual public view returns (uint64);
        function getUtilization() public view returns (uint);
    }
}

/// Input to the guest.
#[derive(Serialize, Deserialize)]
pub struct Input {
    /// Steel input.
    pub input: EthEvmChainInput,
    /// Own image ID; we cannot use a constant as this would modify the image itself.
    pub self_image_id: Digest,
    /// Journal of a previous assumption; if None then we start a new chain.
    pub assumption: Option<Vec<u8>>,
}

sol! {
    /// ABI encodable Journal of the guest.
    struct Journal {
        /// Steel commitment.
        SolCommitment commitment;
        /// Token stats.
        Stats stats;
        /// Input commitment to the own image ID.
        bytes32 selfImageID;
    }

    /// Token statistics.
    #[derive(Default)]
    struct Stats {
        uint256 cumulativeSupplyRate;
        uint64 n;
    }
}

impl Stats {
    pub fn add_supply_rate(&mut self, supply_rate: u64) {
        self.cumulativeSupplyRate += U256::from(supply_rate);
        self.n += 1;
    }

    pub fn average_supply_rate_as_f64(&self) -> f64 {
        let (div, rem) = self.cumulativeSupplyRate.div_rem(U256::from(self.n));
        f64::from(div) + f64::from(rem) / self.n as f64
    }
}
