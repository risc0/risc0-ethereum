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

#![allow(unused_doc_comments)]
#![no_main]

use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{config::ETH_SEPOLIA_CHAIN_SPEC, ethereum::EthViewCallInput, ViewCall};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Specify the function to call using the [`sol!`] macro.
/// This parses the Solidity syntax to generate a struct that implements the [SolCall] trait.
/// The struct instantiated with the arguments can then be passed to the [ViewCall] to execute the
/// call. For example:
/// `IERC20::balanceOfCall { account: address!("9737100D2F42a196DE56ED0d1f6fF598a250E7E4") }`
sol! {
    /// ERC-20 balance function signature.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Function to call, implements [SolCall] trait.
const CALL: IERC20::balanceOfCall =
    IERC20::balanceOfCall { account: address!("9737100D2F42a196DE56ED0d1f6fF598a250E7E4") };

/// Address of the deployed contract to call the function on. Here: USDT contract on Sepolia
const CONTRACT: Address = address!("aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0");
/// Address of the caller of the function. If not provided, the caller will be the [CONTRACT].
const CALLER: Address = address!("f08A50178dfcDe18524640EA6618a1f965821715");

fn main() {
    // Read the input from the guest environment.
    let input: EthViewCallInput = env::read();

    // Converts the input into a `ViewCallEnv` for execution. The `with_chain_spec` method is used
    // to specify the chain configuration. It checks that the state matches the state root in the
    // header provided in the input.
    let view_call_env = input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
    // Commit the block hash and number used when deriving `view_call_env` to the journal.
    env::commit_slice(&view_call_env.block_commitment().abi_encode());

    // Execute the view call; it returns the result in the type generated by the `sol!` macro.
    let returns = view_call_env.execute(ViewCall::new(CALL, CONTRACT).with_caller(CALLER));
    println!("View call result: {}", returns._0);
}
