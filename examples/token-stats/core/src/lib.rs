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

use alloy_primitives::{address, Address};
use alloy_sol_types::sol;
use risc0_steel::Commitment;

/// Address of Compound USDC (cUSDCv3) token.
pub const CONTRACT: Address = address!("c3d688B66703497DAA19211EEdff47f25384cdc3");

sol! {
    /// Simplified interface of the Compound Finance Comet contract
    interface CometMainInterface {
        function getSupplyRate(uint utilization) virtual public view returns (uint64);
        function getUtilization() public view returns (uint);
    }
}

sol! {
    struct APRCommitment {
        Commitment commitment;
        uint64 annualSupplyRate;
    }
}
