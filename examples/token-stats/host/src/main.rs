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
use anyhow::{Context, Result};
use clap::Parser;
use core::{CometMainInterface, Input, Journal, CONTRACT};
use methods::{TOKEN_STATS_ELF, TOKEN_STATS_ID};
use risc0_steel::{config::ETH_MAINNET_CHAIN_SPEC, ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::io::BufWriter;
use std::{fs::File, io::BufReader, path::PathBuf};
use tracing_subscriber::EnvFilter;

// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,
    /// Block number to execute the call on
    #[arg(long)]
    block_number: Option<u64>,
    /// Path of the receipt file.
    #[arg(long, default_value = "receipt.bin")]
    receipt_path: PathBuf,
}

fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // Load the previous receipt from file, if no block number is given.
    let (block_number, receipt) = match args.block_number {
        Some(block_number) => (block_number, None),
        None => {
            let file = File::open(&args.receipt_path)?;
            let receipt: Receipt = bincode::deserialize_from(BufReader::new(file))?;
            receipt.verify(TOKEN_STATS_ID)?;
            let journal = Journal::abi_decode(&receipt.journal.bytes, false)?;
            (
                journal.commitment.blockNumber.to::<u64>() + 1,
                Some(receipt),
            )
        }
    };

    // Create an EVM environment from an RPC endpoint and a block number. If no block number is
    // provided, the latest block is used.
    let mut env = EthEvmEnv::from_rpc(&args.rpc_url, Some(block_number))?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_MAINNET_CHAIN_SPEC);

    let latest = env
        .provider()
        .get_block_number()
        .context("failed to query latest block number")?;

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let utilization = contract
        .call_builder(&CometMainInterface::getUtilizationCall {})
        .call()?
        ._0;
    contract
        .call_builder(&CometMainInterface::getSupplyRateCall { utilization })
        .call()?;

    // Create an input chain from the given block to the latest.
    let input = Input {
        input: env.into_chain_input(latest)?,
        self_image_id: TOKEN_STATS_ID.into(),
        assumption: receipt.clone().map(|r| r.journal.bytes),
    };

    // Run the guest with the constructed input and a previous receipt.
    let prove_info = {
        let mut builder = ExecutorEnv::builder();
        if let Some(receipt) = receipt {
            builder.add_assumption(receipt);
        }
        let env = builder
            .write(&input)
            .unwrap()
            .build()
            .context("failed to initialize prover")?;
        default_prover()
            .prove(env, TOKEN_STATS_ELF)
            .context("failed to create proof")?
    };

    // Save the receipt to add more data points later
    let file = File::create(&args.receipt_path)?;
    bincode::serialize_into(BufWriter::new(file), &prove_info.receipt)?;

    let journal = Journal::abi_decode(&prove_info.receipt.journal.bytes, true)
        .context("failed to decode journal")?;

    // Calculation is handling `/ 10^18 * 100` to match precision for a percentage.
    let apr = journal.stats.average_supply_rate_as_f64() / 10f64.powi(16);
    println!(
        "Proven average APR calculated from {} data points is: {}%",
        journal.stats.n, apr
    );

    Ok(())
}
