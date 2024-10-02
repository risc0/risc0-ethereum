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

use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};
use clap::Parser;
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_MAINNET_CHAIN_SPEC},
    Contract,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use token_stats_core::{APRCommitment, CometMainInterface, CONTRACT};
use token_stats_methods::TOKEN_STATS_ELF;
use tracing_subscriber::EnvFilter;
use url::Url;

// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // Create an EVM environment from an RPC endpoint defaulting to the latest block.
    let mut env = EthEvmEnv::builder().rpc(args.rpc_url).build().await?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_MAINNET_CHAIN_SPEC);

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call()
        .await?
        ._0;
    println!(
        "Call {} Function on {:#} returns: {}",
        CometMainInterface::getUtilizationCall::SIGNATURE,
        CONTRACT,
        utilization
    );
    let rate = contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call()
        .await?
        ._0;
    println!(
        "Call {} Function on {:#} returns: {}",
        CometMainInterface::getSupplyRateCall::SIGNATURE,
        CONTRACT,
        rate
    );

    // Finally, construct the input from the environment.
    let input = env.into_input().await?;

    println!("Running the guest with the constructed input:");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&input)
            .unwrap()
            .build()
            .context("failed to build executor env")?;
        let exec = default_executor();
        exec.execute(env, TOKEN_STATS_ELF)
            .context("failed to run executor")?
    };

    // The journal should be the ABI encoded commitment.
    let apr_commit = APRCommitment::abi_decode(&session_info.journal.bytes, true)
        .context("failed to decode journal")?;
    println!("{:?}", apr_commit.commitment);

    // Calculation is handling `/ 10^18 * 100` to match precision for a percentage.
    let apr = apr_commit.annualSupplyRate as f64 / 10f64.powi(16);
    println!("Proven APR calculated is: {}%", apr);

    Ok(())
}
