// Copyright 2025 RISC Zero, Inc.
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

use alloy_primitives::{address, Address, U256};
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{
    ethereum::{EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Event,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Specify the event to query using the [`sol!`] macro.
sol! {
    /// ERC-20 transfer event signature.
    interface IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}

sol! {
    /// ABI-encodable journal.
    struct Journal {
        Commitment commitment;
        bytes32 blockHash;
        uint256 value;
    }
}

/// Address of the deployed contract to call the function on (USDT contract on Mainnet).
const CONTRACT: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");

fn main() {
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();

    // Converts the input into a `EvmEnv` for execution.
    let env = input.into_env(&ETH_SEPOLIA_CHAIN_SPEC);
    let block_hash = env.header().seal();

    // Query all `Transfer` events of the USDT contract.
    let event = Event::new::<IERC20::Transfer>(&env);
    let logs = event.address(CONTRACT).query();

    // Process the events.
    let value = logs.iter().map(|log| log.data.value).sum::<U256>();

    // This commits the sum of all USDT transfers in the current block into the journal.
    let journal = Journal {
        commitment: env.into_commitment(),
        blockHash: block_hash,
        value,
    };
    env::commit_slice(&journal.abi_encode());
}
