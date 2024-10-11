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
