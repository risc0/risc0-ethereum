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

use alloy_sol_types::SolValue;
use risc0_steel::{
    ethereum::{EthEvmInput, ETH_MAINNET_CHAIN_SPEC},
    Contract, SteelVerifier,
};
use risc0_zkvm::guest::env;
use token_stats_core::{APRCommitment, CometMainInterface, CONTRACT};

const SECONDS_PER_YEAR: u64 = 60 * 60 * 24 * 365;

fn main() {
    // Read the first input from the guest environment. It corresponds to the older EVM state.
    let input: EthEvmInput = env::read();

    // Converts the input into a `EvmEnv` for execution.
    let env_prev = input.into_env(&ETH_MAINNET_CHAIN_SPEC);

    // Execute the view calls on the older EVM state.
    let contract = Contract::new(CONTRACT, &env_prev);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call();
    let supply_rate_prev = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call();

    // Prepare the second `EvmEnv` for execution.  It corresponds to the recent EVM state.
    let input: EthEvmInput = env::read();
    let env_cur = input.into_env(&ETH_MAINNET_CHAIN_SPEC);

    // Verify that the older EVM state is valid wrt the recent EVM state.
    // We initialize the SteelVerifier with the recent state, to check the previous commitment.
    SteelVerifier::new(&env_cur).verify(env_prev.commitment());

    // Execute the view calls also on the recent EVM state.
    let contract = Contract::new(CONTRACT, &env_cur);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call();
    let supply_rate_cur = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call();

    // The formula for APR in percentage is the following:
    // Seconds Per Year = 60 * 60 * 24 * 365
    // Utilization = getUtilization()
    // Supply Rate = getSupplyRate(Utilization)
    // Supply APR = Supply Rate / (10 ^ 18) * Seconds Per Year * 100
    //
    // Compute the average APR, by computing the average over both states.
    let annual_supply_rate = (supply_rate_prev + supply_rate_cur) * SECONDS_PER_YEAR / 2;

    // This commits the APR at current utilization rate for this given block.
    let journal = APRCommitment {
        commitment: env_cur.into_commitment(),
        annualSupplyRate: annual_supply_rate,
    };
    env::commit_slice(&journal.abi_encode());
}
