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

use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{
    config::ETH_SEPOLIA_CHAIN_SPEC, ethereum::EthViewCallInput, Contract, SolCommitment,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Specify the function to call using the [`sol!`] macro.
/// This parses the Solidity syntax to generate a struct that implements the `SolCall` trait.
sol! {
    /// ERC-20 balance function signature.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

sol! {
    struct Journal {
        SolCommitment commitment;
        address tokenAddress;
    }
}

fn main() {
    // Read the input from the guest environment.
    let input: EthViewCallInput = env::read();
    let contract: Address = env::read();
    let account: Address = env::read();

    // Converts the input into a `EvmEnv` for execution. The `with_chain_spec` method is used
    // to specify the chain configuration. It checks that the state matches the state root in the
    // header provided in the input.
    let view_call_env = input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

    // Execute the view call; it returns the result in the type generated by the `sol!` macro.
    let call = IERC20::balanceOfCall { account };
    let returns = Contract::new(contract, &view_call_env)
        .call_builder(&call)
        .call();

    // Check that the given account holds at least 1 token.
    assert!(returns._0 >= U256::from(1));

    // Commit the block hash and number used when deriving `view_call_env` to the journal.
    let journal = Journal {
        commitment: view_call_env.block_commitment(),
        tokenAddress: contract,
    };
    env::commit_slice(&journal.abi_encode());
}
