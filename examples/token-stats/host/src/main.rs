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
use core::{CToken, CONTRACT};
use methods::TOKEN_STATS_ELF;
use risc0_steel::{config::ETH_MAINNET_CHAIN_SPEC, ethereum::EthViewCallEnv, EvmHeader, ViewCall};
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
    let mut env =
        EthViewCallEnv::from_rpc(&args.rpc_url, None)?.with_chain_spec(&ETH_MAINNET_CHAIN_SPEC);
    let number = env.header().number();
    let commitment = env.block_commitment();

    // Preflight the view call to construct the input that is required to execute the function in
    // the guest. It also returns the result of the call.
    let returns = env.preflight(ViewCall::new(CToken::supplyRatePerBlockCall {}, CONTRACT))?;
    let input = env.into_zkvm_input()?;
    println!(
        "For block {} `{}` returns: {}",
        number,
        CToken::supplyRatePerBlockCall::SIGNATURE,
        returns._0,
    );

    println!("Running the guest with the constructed input:");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&input)
            .unwrap()
            .build()
            .context("Failed to build exec env")?;
        let exec = default_executor();
        exec.execute(env, TOKEN_STATS_ELF).context("failed to run executor")?
    };

    // extract the proof from the session info and validate it
    let bytes = session_info.journal.as_ref();
    assert_eq!(&bytes[..64], &commitment.abi_encode());

    Ok(())
}
