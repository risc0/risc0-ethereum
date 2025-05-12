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

use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};
use clap::Parser;
use risc0_steel::{
    alloy::providers::{Provider, ProviderBuilder},
    ethereum::{EthEvmEnv, ETH_MAINNET_CHAIN_SPEC},
    Contract, SteelVerifier,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use token_stats_core::{APRCommitment, CometMainInterface, CONTRACT};
use token_stats_methods::TOKEN_STATS_ELF;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(long, env = "RPC_URL")]
    rpc_url: Url,

    /// Beacon API endpoint URL
    #[arg(long, env = "BEACON_API_URL")]
    beacon_api_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // Query the latest block number.
    let provider = ProviderBuilder::default().connect_http(args.rpc_url);
    let latest = provider.get_block_number().await?;

    // Create an EVM environment for that provider and about 12h (3600 blocks) ago.
    let mut env = EthEvmEnv::builder()
        .provider(provider.clone())
        .block_number(latest - 3600)
        .beacon_api(args.beacon_api_url)
        .chain_spec(&ETH_MAINNET_CHAIN_SPEC)
        .build()
        .await?;

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call()
        .await?;
    println!(
        "Call {} Function on {:#} returns: {}",
        CometMainInterface::getUtilizationCall::SIGNATURE,
        CONTRACT,
        utilization
    );
    let rate = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call()
        .await?;
    println!(
        "Call {} Function on {:#} returns: {}",
        CometMainInterface::getSupplyRateCall::SIGNATURE,
        CONTRACT,
        rate
    );

    // Construct the commitment and input from the environment representing the state 12h ago.
    let commitment_input1 = env.commitment();
    let input1 = env.into_input().await?;

    // Create another EVM environment for that provider defaulting to the latest block.
    let mut env = EthEvmEnv::builder()
        .provider(provider)
        .chain_spec(&ETH_MAINNET_CHAIN_SPEC)
        .build()
        .await?;

    // Preflight the verification of the commitment of the previous input.
    SteelVerifier::preflight(&mut env)
        .verify(&commitment_input1)
        .await?;

    // Preflight the actual contract calls.
    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call()
        .await?;
    println!(
        "Call {} Function on {:#} returns: {}",
        CometMainInterface::getUtilizationCall::SIGNATURE,
        CONTRACT,
        utilization
    );
    let rate = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call()
        .await?;
    println!(
        "Call {} Function on {:#} returns: {}",
        CometMainInterface::getSupplyRateCall::SIGNATURE,
        CONTRACT,
        rate
    );

    // Finally, construct the second input from the environment representing the latest state.
    let input2 = env.into_input().await?;

    println!("Running the guest with the constructed input:");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&input1)
            .unwrap()
            .write(&input2)
            .unwrap()
            .build()
            .context("failed to build executor env")?;
        let exec = default_executor();
        exec.execute(env, TOKEN_STATS_ELF)
            .context("failed to run executor")?
    };

    // The journal should be the ABI encoded commitment.
    let apr_commit = APRCommitment::abi_decode(&session_info.journal.bytes)
        .context("failed to decode journal")?;
    println!("{:?}", apr_commit.commitment);

    // Calculation is handling `/ 10^18 * 100` to match precision for a percentage.
    let apr = apr_commit.annualSupplyRate as f64 / 10f64.powi(16);
    println!("Proven APR calculated is: {}%", apr);

    Ok(())
}
