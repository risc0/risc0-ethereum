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

use alloy_sol_types::SolValue;
use risc0_steel::{
    ethereum::{EthEvmInput, ETH_MAINNET_CHAIN_SPEC},
    Contract, SteelVerifier,
};
use risc0_zkvm::guest::env;
use token_stats_core::{APRCommitment, CometMainInterface, CONTRACT};

const SECONDS_PER_YEAR: u64 = 60 * 60 * 24 * 365;

fn main() {
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();

    // Converts the input into a `EvmEnv` for execution.
    let env1 = input.into_env().with_chain_spec(&ETH_MAINNET_CHAIN_SPEC);

    // Execute the view calls; it returns the result in the type generated by the `sol!` macro.
    let contract = Contract::new(CONTRACT, &env1);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call()
        ._0;
    let supply_rate_1 = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call()
        ._0;

    // Prepare the second `EvmEnv` for execution.
    let input: EthEvmInput = env::read();
    let env2 = input.into_env().with_chain_spec(&ETH_MAINNET_CHAIN_SPEC);

    // Verify the first commitment.
    SteelVerifier::new(&env2).verify(env1.commitment());

    // Execute the view calls; it returns the result in the type generated by the `sol!` macro.
    let contract = Contract::new(CONTRACT, &env2);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call()
        ._0;
    let supply_rate_2 = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call()
        ._0;

    // The formula for APR in percentage is the following:
    // Seconds Per Year = 60 * 60 * 24 * 365
    // Utilization = getUtilization()
    // Supply Rate = getSupplyRate(Utilization)
    // Supply APR = Supply Rate / (10 ^ 18) * Seconds Per Year * 100
    //
    // And this is calculating: Supply Rate * Seconds Per Year, to avoid float calculations for
    // precision.
    let annual_supply_rate = supply_rate_1 * SECONDS_PER_YEAR;
    // compute the average
    let annual_supply_rate = (annual_supply_rate + supply_rate_2 * SECONDS_PER_YEAR) / 2;

    // This commits the APR at current utilization rate for this given block.
    let journal = APRCommitment {
        commitment: env2.into_commitment(),
        annualSupplyRate: annual_supply_rate,
    };
    env::commit_slice(&journal.abi_encode());
}
