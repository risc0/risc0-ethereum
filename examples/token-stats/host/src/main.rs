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

use alloy_primitives::{Sealable, U256};
use alloy_sol_types::SolValue;
use anyhow::{Context, Result};
use clap::Parser;
use core::{APRCommitment, CometMainInterface, CONTRACT};
use methods::TOKEN_STATS_ELF;
use risc0_steel::{
    config::ETH_MAINNET_CHAIN_SPEC,
    ethereum::EthViewCallEnv,
    host::{
        provider::{EthersProvider, Provider},
        EthersClient,
    },
    BlockCommitment, ViewCall,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use tracing_subscriber::EnvFilter;

// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: String,
}

fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    // parse the command line arguments
    let args = Args::parse();

    // Create a view call environment from an RPC endpoint and a block number. If no block number is
    // provided, the latest block is used. The `with_chain_spec` method is used to specify the
    // chain configuration.
    let client = EthersClient::new_client(&args.rpc_url, 3, 500)?;
    let provider = EthersProvider::new(client);
    let head_block_num = provider.get_block_number()?;

    // Take a block x behind head, to check hash linking to commitment
    let query_block_num = head_block_num - 100;

    let headers_from_query: Vec<_> = (query_block_num + 1..head_block_num)
        .into_iter()
        .map(|block_num| {
            provider
                .get_block_header(block_num)
                .with_context(|| format!("could not retrieve block {block_num}"))?
                .with_context(|| format!("block at height {block_num} not found"))
        })
        .collect::<Result<_>>()?;

    let mut env = EthViewCallEnv::from_provider(provider, query_block_num)?
        .with_chain_spec(&ETH_MAINNET_CHAIN_SPEC);

    // Preflight the view call to construct the input that is required to execute the function in
    // the guest. It also returns the result of the call.
    let utilization =
        env.preflight(ViewCall::new(CometMainInterface::getUtilizationCall {}, CONTRACT))?._0;
    env.preflight(ViewCall::new(CometMainInterface::getSupplyRateCall { utilization }, CONTRACT))?
        ._0;
    let input = env.into_zkvm_input()?;

    println!("Running the guest with the constructed input:");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&input)?
            .write(&headers_from_query)?
            .build()
            .context("Failed to build exec env")?;
        let exec = default_executor();
        exec.execute(env, TOKEN_STATS_ELF).context("failed to run executor")?
    };

    let new_block_commitment = headers_from_query
        .last()
        .map(|h| BlockCommitment { blockHash: h.hash_slow(), blockNumber: U256::from(h.number) })
        .unwrap();
    let apr_commit = APRCommitment::abi_decode(&session_info.journal.bytes, true)?;
    assert_eq!(apr_commit.commitment, new_block_commitment);

    // Calculation is handling `/ 10^18 * 100` to match precision for a percentage.
    let apr = apr_commit.annualSupplyRate as f64 / 10f64.powi(16);
    println!("Compound APR proven at height {} is: {}%", apr_commit.queryHeight, apr);

    Ok(())
}
